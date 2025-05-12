<?php

namespace Tests\Webrtc\SSL\SSL;

use DateInterval;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use Webrtc\SSL\Crypto\EC\EC;
use Webrtc\SSL\Crypto\EvpPKey;
use Webrtc\SSL\Crypto\PrivateKeyInterface;
use Webrtc\SSL\Crypto\X509;
use Webrtc\SSL\Enum\BioMethod;
use Webrtc\SSL\Enum\ContextMethod;
use Webrtc\SSL\Enum\ECCurveName;
use Webrtc\SSL\Enum\Verify;
use Webrtc\SSL\Exception\WantReadException;
use Webrtc\SSL\Exception\ZeroReturnException;
use Webrtc\SSL\OpenSSL;
use Webrtc\SSL\SSL\BIO;
use Webrtc\SSL\SSL\Context;
use Webrtc\SSL\SSL\SSL;

#[UsesClass(EC::class)]
#[UsesClass(EvpPKey::class)]
#[UsesClass(X509::class)]
#[UsesClass(OpenSSL::class)]
#[UsesClass(BIO::class)]
#[UsesClass(Context::class)]
#[CoversClass(SSL::class)]
class SSLTest extends TestCase
{
    private const array SUPPORTED_CIPHER_SUITES = [
        // AES-128-GCM-SHA256
        "ECDHE-ECDSA-AES128-GCM-SHA256",
        "ECDHE-RSA-AES128-GCM-SHA256",

        // AES-256-CBC-SHA
        "ECDHE-ECDSA-AES256-SHA",
        "ECDHE-RSA-AES256-SHA",

        // AES-256-GCM-SHA384
        "ECDHE-ECDSA-AES256-GCM-SHA384",
        "ECDHE-RSA-AES256-GCM-SHA384"
    ];

    protected function setUp(): void
    {
        parent::setUp();
        OpenSSL::init();
    }

    public function testGetContext()
    {
        $context = new Context(ContextMethod::DTLS_METHOD);
        $bio = new Bio(BioMethod::s_mem, BioMethod::s_mem);
        $ssl = new SSL($context, $bio);

        $this->assertSame($context, $ssl->getContext());
    }

    public function testTLSHandShakeSuccess()
    {
        [$clientSsl, $clientBio] = $this->generateSSL(true);
        [$serverSsl, $serverBio] = $this->generateSSL();

        $this->assertEquals(0, $clientSsl->getState());
        $this->assertEquals(0, $serverSsl->getState());

        $this->assertEquals(0, $clientSsl->getVerify());
        $this->assertEquals(0, $serverSsl->getVerify());

        $res = $this->doHandshake($clientSsl, $serverSsl, $clientBio, $serverBio);
        $this->assertTrue($res);

        $this->assertEquals(1, $clientSsl->getState());
        $this->assertEquals(1, $serverSsl->getState());

        // 18 means: Handshake successful, but the certificate verification failed because the certificate is self-signed, and its verification depth is zero.
        $this->assertEquals(18, $clientSsl->getVerify());
        $this->assertEquals(18, $serverSsl->getVerify());
    }

    public function testShutdown()
    {
        [$clientSsl, $clientBio] = $this->generateSSL(true);
        [$serverSsl, $serverBio] = $this->generateSSL();

        $res = $this->doHandshake($clientSsl, $serverSsl, $clientBio, $serverBio);
        $this->assertTrue($res);

        $this->assertTrue($serverSsl->shutdown());

        // Send a shutdown message to the client
        $clientBio->write($serverBio->read());

        $this->expectException(ZeroReturnException::class);
        $this->expectExceptionMessage("Zero returned");
        $clientSsl->read(1500);

        $this->assertTrue($clientSsl->shutdown());

        // Send a shutdown message to the server
        $serverBio->write($clientBio->read());

        $this->expectException(ZeroReturnException::class);
        $this->expectExceptionMessage("Zero returned");
        $serverSsl->read(1500);

        $this->assertTrue($clientSsl->shutdown());
        $this->assertTrue($serverSsl->shutdown());
    }

    public function testShutdownTruncated()
    {
        [$clientSsl, $clientBio] = $this->generateSSL(true);
        [$serverSsl, $serverBio] = $this->generateSSL();

        $res = $this->doHandshake($clientSsl, $serverSsl, $clientBio, $serverBio);
        $this->assertTrue($res);

        $this->assertTrue($serverSsl->shutdown());

        $this->expectException(WantReadException::class);
        $serverSsl->shutdown();
    }

    public function testHandshakeAndDataWithSrtp()
    {
        $srtpProfile = "SRTP_AES128_CM_SHA1_80";

        [$clientSsl, $clientBio, $clientCtx] = $this->generateSSL(true);
        [$serverSsl, $serverBio, $serverCtx] = $this->generateSSL();

        $clientCtx->setTlsextUseSrtp($srtpProfile);
        $serverCtx->setTlsextUseSrtp($srtpProfile);

        $res = $this->doHandshake($clientSsl, $serverSsl, $clientBio, $serverBio);
        $this->assertTrue($res);

        $this->assertEquals($srtpProfile, $serverSsl->getSelectedSrtpProfile());
        $this->assertEquals($srtpProfile, $clientSsl->getSelectedSrtpProfile());

        $this->assertEquals(60, strlen($serverSsl->exportKeyingMaterial("EXTRACTOR-dtls_srtp", 60)));
        $this->assertEquals(60, strlen($clientSsl->exportKeyingMaterial("EXTRACTOR-dtls_srtp", 60)));

        $message = "Hello!";

        // Server encryption
        $serverSsl->write($message);
        $encrypted = $serverBio->read();

        // Client decryption
        $clientBio->write($encrypted);
        $decrypted = $clientSsl->read(1500);

        $this->assertEquals($message, rtrim($decrypted, "\0"));

        $message2 = "Bye!";

        // Client encryption
        $clientSsl->write($message2);
        $encrypted = $clientBio->read();

        // Server decryption
        $serverBio->write($encrypted);
        $decrypted = $serverSsl->read(1500);

        $this->assertEquals($message2, rtrim($decrypted, "\0"));
    }

    public function testTimeout()
    {
        [$clientSsl, $clientBio] = $this->generateSSL(true);
        [$serverSsl, $serverBio] = $this->generateSSL();

        // No timeout before the handshake starts.
        $this->assertNull($serverSsl->DTLSv1GetTimeout());
        $this->assertFalse($serverSsl->DTLSv1HandleTimeout());

        $this->assertNull($clientSsl->DTLSv1GetTimeout());
        $this->assertFalse($clientSsl->DTLSv1HandleTimeout());

        $res = $this->doHandshake($clientSsl, $serverSsl, $clientBio, $serverBio);
        $this->assertTrue($res);

        // FIXME: For testing it needs async but I dont want to add any package in dev at this moment
    }

    public function testPeerCertificateDigits()
    {
        [$clientSsl, $clientBio, , $clientCert] = $this->generateSSL(true);
        [$serverSsl, $serverBio, , $serverCert] = $this->generateSSL();

        $res = $this->doHandshake($clientSsl, $serverSsl, $clientBio, $serverBio);
        $this->assertTrue($res);

        $this->assertEquals($clientCert->getDigits("sha256"), $serverSsl->getPeerCertificateDigest());
        $this->assertEquals($serverCert->getDigits("sha256"), $clientSsl->getPeerCertificateDigest());
    }

    /**
     * @param bool $client
     * @return array{SSL, BIO, Context, X509} Returns an array containing SSL, BIO, Context, and X509 objects.
     */
    private function generateSSL(bool $client = false): array
    {
        $key = $this->generatePrivateKey();
        $cert = $this->generateCertificate($key);

        $context = new Context(ContextMethod::DTLS_METHOD);
        $context->setVerify(Verify::PEER->value | Verify::FAIL_IF_NO_PEER_CERT->value, fn(...$args) => true);
        $context->setCipherList(implode(":", self::SUPPORTED_CIPHER_SUITES));
        $context->usePrivateKey($key);
        $context->useCertificate($cert);

        $bio = new Bio(BioMethod::s_mem, BioMethod::s_mem);
        $bio->setBufferSize(1500);

        $ssl = new SSL($context, $bio);
        if ($client) {
            $ssl->setConnectState();
        } else {
            $ssl->setAcceptState();
        }

        return [$ssl, $bio, $context, $cert];
    }

    private function doHandshake(SSL $client, SSL $server, BIO $clientBio, BIO $serverBio): bool
    {
        $serverHandshake = false;
        $clientHandshake = false;

        while (true) {
            if (!$clientHandshake) {
                try {
                    $client->doHandshake();
                    $data = $clientBio->read();
                    if ($data && strlen($data) > 0) {
                        $serverBio->write($data);
                    }
                    $clientHandshake = true;
                } catch (WantReadException) {
                    $data = $clientBio->read();
                    if ($data && strlen($data) > 0) {
                        $serverBio->write($data);
                    }
                } catch (\Throwable) {
                    return false;
                }
            }

            if (!$serverHandshake) {
                try {
                    $server->doHandshake();
                    $data = $serverBio->read();
                    if ($data && strlen($data) > 0) {
                        $clientBio->write($data);
                    }
                    $serverHandshake = true;
                } catch (WantReadException) {
                    $data = $serverBio->read();
                    if ($data && strlen($data) > 0) {
                        $clientBio->write($data);
                    }
                } catch (\Throwable) {
                    return false;
                }
            }

            if ($clientHandshake && $serverHandshake) {
                return true;
            }
        }
    }

    private function generatePrivateKey(): EC
    {
        $ecKey = new EC(ECCurveName::secp256r1);
        $ecKey->generate();

        return $ecKey;
    }

    private function generateCertificate(PrivateKeyInterface $key): X509
    {
        $x509 = new X509();

        $x509->setSerialNumberDefualt();

        $now = new DateTimeImmutable();
        $x509->setDateNotBefore($now->sub(new DateInterval('P1D'))); // The certificate validity started from a day ago.
        $x509->setDateNotAfter($now->add(new DateInterval('P30D'))); // The certificate is valid until 30 days from now.

        $x509->setPublicKey($key);

        $x509->setSubjectName();

        $x509->addEntry("C", 'US');
        $x509->addEntry("ST", 'VA');
        $x509->addEntry("L", 'Fairfax');
        $x509->addEntry("O", 'Quasar Stream');
        $x509->addEntry("CN", 'https://www.quasarstream.com');

        $x509->setIssuerName();

        $x509->sign($key);

        return $x509;
    }
}
