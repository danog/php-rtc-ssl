<?php

namespace Tests\Webrtc\SSL\SSL;

use DateInterval;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use Webrtc\Exception\RuntimeException;
use Webrtc\SSL\Crypto\EC\EC;
use Webrtc\SSL\Crypto\EvpPKey;
use Webrtc\SSL\Crypto\PrivateKeyInterface;
use Webrtc\SSL\Crypto\X509;
use Webrtc\SSL\Enum\BioMethod;
use Webrtc\SSL\Enum\ContextMethod;
use Webrtc\SSL\Enum\ECCurveName;
use Webrtc\SSL\OpenSSL;
use Webrtc\SSL\SSL\BIO;
use Webrtc\SSL\SSL\Context;
use Webrtc\SSL\SSL\SSL;

#[UsesClass(OpenSSL::class)]
#[UsesClass(EC::class)]
#[UsesClass(EvpPKey::class)]
#[UsesClass(X509::class)]
#[UsesClass(BIO::class)]
#[UsesClass(SSL::class)]
#[CoversClass(Context::class)]
class ContextTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        OpenSSL::init();
    }

    public function testSetCipherList()
    {
        $context = new Context(ContextMethod::DTLS_METHOD);
        $context->setCipherList("hello world:AES128-SHA");

        $ssl = new SSL($context, new BIO(BioMethod::s_mem));
        $this->assertContains('AES128-SHA', $ssl->getCipherList());
    }

    public function testSetCipherListWrongType()
    {
        $context = new Context(ContextMethod::DTLS_METHOD);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Wrong cipher list!');
        $context->setCipherList("wrong cipher"); // Non-string argument
    }

    public function testWrongPrivateKeyFileWrongFile()
    {
        $context = new Context(ContextMethod::DTLS_METHOD);

        $invalidPath = ["//a.pem"]; // Fixme
        foreach ($invalidPath as $filePath) {
            $this->expectException(RuntimeException::class);
            $this->expectExceptionMessage('Failed to load private key file or corrupted file');
            $context->usePrivatekeyFile($filePath);
        }
    }

    public function testUsePrivateKeyFile()
    {
        $filePath = __DIR__ . "/../fixture/private_key.pem";
        $filePath2 = __DIR__ . "/../fixture/wrong_private_key.key";

        $context = new Context(ContextMethod::DTLS_METHOD);
        $context->usePrivatekeyFile($filePath); // If didn't throw any exceptions, the key is OK
        $this->assertFileExists($filePath);

        $context->usePrivatekeyFile($filePath2); // If didn't throw any exceptions, the key is OK
        $this->assertFileExists($filePath2);
    }

    public function testUseCertificateFileWrongFile()
    {
        $context = new Context(ContextMethod::DTLS_METHOD);

        $invalidPath = ["//a.pem"]; // Fixme
        foreach ($invalidPath as $filePath) {
            $this->expectException(RuntimeException::class);
            $this->expectExceptionMessage('Failed to load cert file or corrupted file');
            $context->useCertificateFile($filePath);
        }
    }

    public function testUseCertificateFile()
    {
        $filePath = __DIR__ . "/../fixture/certificate.pem";

        $context = new Context(ContextMethod::DTLS_METHOD);
        $context->useCertificateFile($filePath); // If didn't throw any exceptions, the key is OK
        $this->assertFileExists($filePath);
    }

    public function testCheckPrivateKeyAndCertificateInvalid()
    {
        $key = __DIR__ . "/../fixture/wrong_private_key.key";
        $cert = __DIR__ . "/../fixture/certificate.pem";

        $context = new Context(ContextMethod::DTLS_METHOD);
        $context->usePrivateKeyFile($key);
        $context->useCertificateFile($cert);
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Private key does not match the certificate public key');
        $context->checkPrivatekey();
    }

    public function testCheckPrivateKeyAndCertificateValid()
    {
        $key = __DIR__ . "/../fixture/private_key.pem";
        $cert = __DIR__ . "/../fixture/certificate.pem";

        $context = new Context(ContextMethod::DTLS_METHOD);
        $context->usePrivateKeyFile($key);
        $context->useCertificateFile($cert);
        $context->checkPrivatekey(); // If didn't throw any exceptions, the key and cert are OK
        $this->assertFileExists($key);
    }

    public function testUsePrivateKey()
    {
        $key = $this->generatePrivateKey();

        $context = new Context(ContextMethod::DTLS_METHOD);
        $context->usePrivateKey($key); // If didn't throw any exceptions, the key is OK
        $this->assertTrue(true);
    }

    public function testUseCertificate()
    {
        $key = $this->generatePrivateKey();
        $cert = $this->generateCertificate($key);

        $context = new Context(ContextMethod::DTLS_METHOD);
        $context->useCertificate($cert); // If didn't throw any exceptions, the key is OK
        $this->assertTrue(true);
    }

    public function testSetModeOutOfRang()
    {
        $context = new Context(ContextMethod::DTLS_METHOD);

        $this->expectException(RuntimeException::class);
        $context->setMode(-1000); // wrong mode
    }

    public function testSetMode()
    {
        $context = new Context(ContextMethod::DTLS_METHOD);

        $newMode = $context->setMode(SSL_MODE_ENABLE_PARTIAL_WRITE);
        $this->assertEquals(SSL_MODE_ENABLE_PARTIAL_WRITE, $newMode & SSL_MODE_ENABLE_PARTIAL_WRITE);
    }

    public function testSetTlsextUseSrtpInvalidProfile()
    {
        $context = new Context(ContextMethod::DTLS_METHOD);

        $this->expectException(RuntimeException::class);
        $context->setTlsextUseSrtp('WRONG_PARAM');
    }

    public function testSetTlsextUseSrtpValid()
    {
        $context = new Context(ContextMethod::DTLS_METHOD);

        $context->setTlsextUseSrtp('SRTP_AES128_CM_SHA1_80'); // No exception value means success
        $this->assertTrue(true);
    }

    private function generatePrivateKey(): EC
    {
        $ecKey =  new EC(ECCurveName::secp256r1);
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
