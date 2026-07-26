<?php

/**
 * This file is part of the PHP WebRTC package, vendored and modified for MadelineProto.
 *
 * (c) Amin Yazdanpanah <https://www.aminyazdanpanah.com/#contact>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Webrtc\SSL\SSL;

use Webrtc\Exception\RuntimeException;
use Webrtc\SSL\DTLS\Engine;
use Webrtc\SSL\Exception\SSLException;
use Webrtc\SSL\Exception\WantReadException;
use Webrtc\SSL\Exception\ZeroReturnException;

/**
 * A DTLS connection, driving the pure-PHP {@see Engine} through the {@see BIO} datagram queues.
 *
 * The interface mirrors the subset of OpenSSL's `SSL_*` API the rest of the stack relies on, so
 * that the transport and handshake drivers did not have to change when the FFI binding was
 * replaced by a native implementation.
 */
class SSL implements SSLInterface
{
    private Engine $engine;

    public function __construct(
        private readonly Context $context,
        private readonly BIO $bio,
    ) {
        $certificate = $context->getCertificate();
        if ($certificate === null) {
            throw new RuntimeException('The SSL context has no certificate!');
        }
        // Honour what the context was told to offer. Ignoring it meant setTlsextUseSrtp() had
        // no effect at all: every handshake offered the full list regardless, so a peer could
        // end up on a profile the caller never asked for.
        $this->engine = new Engine($certificate, $context->getSrtpProfiles());
    }

    public function setAcceptState(): void
    {
        $this->engine->setAcceptState();
    }

    public function setConnectState(): void
    {
        $this->engine->setConnectState();
    }

    /**
     * Advance the handshake by one step.
     *
     * Feeds everything the transport delivered into the engine, flushes whatever the engine wants
     * to send, and reports whether more data is still needed.
     *
     * @throws WantReadException If the handshake needs another datagram from the peer.
     * @throws SSLException On a fatal protocol violation.
     */
    public function doHandshake(): void
    {
        $this->engine->startHandshake();

        while (($datagram = $this->bio->takeInbound()) !== null) {
            $this->engine->handleDatagram($datagram);
        }
        $this->flush();

        if (!$this->engine->isHandshakeComplete()) {
            throw new WantReadException('The DTLS handshake needs more data from the peer.');
        }
    }

    /**
     * Move everything the engine produced into the outbound queue.
     */
    private function flush(): void
    {
        foreach ($this->engine->takeOutgoing() as $datagram) {
            $this->bio->pushOutbound($datagram);
        }
    }

    public function getPeerCertificateDigest(): ?string
    {
        return $this->engine->getPeerCertificateDigest();
    }

    public function getSelectedSrtpProfile(): string
    {
        return $this->engine->getSelectedSrtpProfile();
    }

    public function exportKeyingMaterial(string $label, int $keyLength, ?string $context = null): string
    {
        return $this->engine->exportKeyingMaterial($label, $keyLength, $context);
    }

    public function shutdown(): bool
    {
        $result = $this->engine->shutdown();
        $this->flush();
        return $result;
    }

    /**
     * Seconds until the current handshake flight must be retransmitted, if a timer is armed.
     */
    public function dtlsV1GetTimeout(): ?float
    {
        return $this->engine->getTimeout();
    }

    /**
     * Retransmit the last flight if its timer expired.
     */
    public function dtlsV1HandleTimeout(): bool
    {
        $retransmitted = $this->engine->handleTimeout();
        $this->flush();
        return $retransmitted;
    }

    /**
     * Read decrypted application data.
     *
     * @throws WantReadException If nothing has arrived yet.
     */
    public function read(int $bufsiz, ?int $flags = null): string
    {
        while (($datagram = $this->bio->takeInbound()) !== null) {
            $this->engine->handleDatagram($datagram);
        }
        $this->flush();

        if ($this->engine->pendingApplicationData() === 0) {
            // Application data that arrived before the alert is still delivered first; only once
            // it has been drained does a received close_notify become a clean end of stream.
            // Callers distinguish this from "nothing yet" to tear the transport down, so
            // reporting WantRead here would leave them connected to a peer that has gone away.
            if ($this->engine->isClosed()) {
                throw new ZeroReturnException('The peer closed the DTLS connection.');
            }

            throw new WantReadException('No application data is available yet.');
        }
        return $this->engine->read($bufsiz);
    }

    /**
     * Encrypt and queue application data.
     *
     * @throws SSLException If the handshake has not completed.
     */
    public function write(string $buf, int $flags = 0): void
    {
        $this->engine->write($buf);
        $this->flush();
    }

    /**
     * The engine behind this connection.
     */
    public function getEngine(): Engine
    {
        return $this->engine;
    }
}
