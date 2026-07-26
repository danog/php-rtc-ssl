<?php

namespace Tests\Webrtc\SSL\Crypto;

use DateTimeImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use Webrtc\Exception\RuntimeException;
use Webrtc\SSL\Crypto\EC\EC;
use Webrtc\SSL\Crypto\EvpPKey;
use Webrtc\SSL\Crypto\X509;
use Webrtc\SSL\Enum\ECCurveName;
use Webrtc\SSL\Exception\OpenSSLException;
use Webrtc\SSL\OpenSSL;

#[UsesClass(OpenSSL::class)]
#[UsesClass(EC::class)]
#[UsesClass(EvpPKey::class)]
#[CoversClass(X509::class)]
class X509Test extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        OpenSSL::init();
    }

    public function testSignWithUngenerated()
    {
        $cert = new X509();
        $key = $this->generatePrivateKey();

        $this->expectException(OpenSSLException::class);
        $cert->sign($key);
    }

    public function testSignWithPublicKey()
    {
        $cert = new X509();
        $key = $this->generatePrivateKey();
        $cert->setPublicKey($key);
        $pub = $cert->getPublicKey();

        $cert->sign($pub);
        $this->assertTrue(true); // No exception means success
    }

    public function testConstruction()
    {
        $certificate = new X509();
        $this->assertInstanceOf(X509::class, $certificate);
    }

    public function testVersion()
    {
        $cert = new X509();
        $cert->setVersion(2);
        $this->assertEquals(2, $cert->getVersion());
    }

    public function testSerialNumber()
    {
        $certificate = new X509();

        $this->assertEquals(0, $certificate->getSerialNumber());

        $certificate->setSerialNumberDefualt();
        $this->assertEquals(1, $certificate->getSerialNumber());

        $certificate->setSerialNumber(2);
        $this->assertEquals(2, $certificate->getSerialNumber());

        $certificate->setSerialNumber(2 ** 32 + 1);
        $this->assertEquals(2 ** 32 + 1, $certificate->getSerialNumber());

        $bigNum1 = "18446744073709551617"; // 2^64 + 1
        $certificate->setSerialNumber($bigNum1);
        $this->assertEquals($bigNum1, $certificate->getSerialNumber());

        $bigNum2 = "340282366920938463463374607431768211457"; // 2^128 + 1
        $certificate->setSerialNumber($bigNum2);
        $this->assertEquals($bigNum2, $certificate->getSerialNumber());
    }

    private function DataTimeTest(callable $get, callable $set): void
    {
        $certificate = new X509();

        $this->assertNull($get($certificate));

        $when = DateTimeImmutable::createFromFormat('YmdHis\Z', '20300203040506Z');
        $set($certificate, $when);
        $this->assertEquals($when, $get($certificate));

        $when = DateTimeImmutable::createFromFormat('YmdHisO', '20300203040506+0530');;
        $set($certificate, $when);
        $this->assertEquals($when, $get($certificate));

        $when = $dateTime = DateTimeImmutable::createFromFormat('YmdHisO', '20300203040506-0115');
        $set($certificate, $when);
        $this->assertEquals($when, $get($certificate));
    }

    public function testSetNotBefore()
    {
        $this->DataTimeTest(fn(X509 $c) => $c->getDateNotBefore(), fn(X509 $c, DateTimeImmutable $v) => $c->setDateNotBefore($v));
    }

    public function testSetNotAfter()
    {
        $this->DataTimeTest(fn(X509 $c) => $c->getDateNotAfter(), fn(X509 $c, DateTimeImmutable $v) => $c->setDateNotAfter($v));
    }

    public function testGetNotBefore()
    {
        $cert = $this->loadCertificate();
        $this->assertEquals(
            DateTimeImmutable::createFromFormat('Y-m-d H:i:s.u', '2025-03-14 00:31:17.000000'),
            $cert->getDateNotBefore()
        );
    }

    public function testGetNotAfter()
    {
        $cert = $this->loadCertificate();
        $this->assertEquals(
            DateTimeImmutable::createFromFormat('Y-m-d H:i:s.u', '2026-03-14 00:31:17.000000'),
            $cert->getDateNotAfter()
        );
    }

    public function testDigest()
    {
        $cert = $this->loadCertificate();
        $this->assertEquals(
            '80:D6:8B:31:64:AA:3C:A8:39:17:C0:DC:B2:D9:2D:31:32:10:24:F5:E1:8E:DF:39:20:F8:9D:75:D1:57:C1:9E',
            $cert->getDigits('SHA256')
        );
    }

    public function testNullbyteSubjectAltName()
    {
        $cert = $this->loadCertificate();

        $this->expectException(RuntimeException::class);
        $cert->getExtension(0);
    }

    public function testGetSubject()
    {
        $cert = $this->loadCertificate();
        $subj = $cert->getSubject();
        $this->assertEquals([
            'countryName' => 'US',
            'stateOrProvinceName' => 'Virginia',
            'localityName' => 'Fairfax',
            'organizationName' => 'Quasar Stream',
            'organizationalUnitName' => 'IT',
            'commonName' => 'Amin',
            'emailAddress' => '@quasarstream.com'
        ], $subj);
    }

    public function testSetSubject()
    {
        $cert = new X509();

        $cert->setSubjectName();

        $cert->addEntry("C", 'US');
        $cert->addEntry("ST", 'Virginia');
        $cert->addEntry("L", 'Fairfax');
        $cert->addEntry("O", 'Quasar Stream');
        $cert->addEntry("CN", 'QuasarStream.com');

        $this->assertEquals([
            'countryName' => 'US',
            'stateOrProvinceName' => 'Virginia',
            'localityName' => 'Fairfax',
            'organizationName' => 'Quasar Stream',
            'commonName' => 'QuasarStream.com'
        ], $cert->getSubject());
    }

    public function testGetIssuer()
    {
        $cert = $this->loadCertificate();
        $subj = $cert->getIssuer();
        $this->assertEquals([
            'countryName' => 'US',
            'stateOrProvinceName' => 'Virginia',
            'localityName' => 'Fairfax',
            'organizationName' => 'Quasar Stream',
            'organizationalUnitName' => 'IT',
            'commonName' => 'Amin',
            'emailAddress' => '@quasarstream.com'
        ], $subj);
    }

    public function testSetIssuer()
    {
        $cert = new X509();
        $cert->setSubjectName();

        $cert->addEntry("C", 'US');
        $cert->addEntry("ST", 'Virginia');
        $cert->addEntry("L", 'Fairfax');
        $cert->addEntry("O", 'Quasar Stream');
        $cert->addEntry("CN", 'QuasarStream.com');

        $cert->setIssuerName();

        $this->assertEquals([
            'countryName' => 'US',
            'stateOrProvinceName' => 'Virginia',
            'localityName' => 'Fairfax',
            'organizationName' => 'Quasar Stream',
            'commonName' => 'QuasarStream.com',
        ], $cert->getIssuer());
    }

    public function testSubjectNameHash()
    {
        $cert = $this->loadCertificate();
        $this->assertEquals(1493627233, $cert->subjectNameHash());
    }

    public function testGetSignatureAlgorithm()
    {
        $cert = $this->loadCertificate();
        $this->assertEquals('ecdsa-with-SHA256', $cert->getSignatureAlgorithm());
    }

    public function testExpires()
    {
        $cert = $this->loadCertificate();
        $this->assertEquals(
            DateTimeImmutable::createFromFormat('Y-m-d H:i:s.u', '2026-03-14 00:31:17.000000'),
            $cert->getExpires()
        );
    }

    private function loadCertificate(): X509
    {
        $path = __DIR__ . "/../fixture/certificate.pem";
        return X509::loadFile($path);
    }

    private function generatePrivateKey(): EC
    {
        $ecKey = new EC(ECCurveName::secp256r1);
        $ecKey->generate();

        return $ecKey;
    }
}
