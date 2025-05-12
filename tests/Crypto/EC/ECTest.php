<?php

namespace Tests\Webrtc\SSL\Crypto\EC;

use FFI\CData;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use Webrtc\SSL\Crypto\EC\EC;
use PHPUnit\Framework\TestCase;
use Webrtc\SSL\Crypto\EvpPKey;
use Webrtc\SSL\Enum\ECCurveName;
use Webrtc\SSL\OpenSSL;

#[UsesClass(EvpPKey::class)]
#[UsesClass(OpenSSL::class)]
#[CoversClass(EC::class)]
class ECTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        OpenSSL::init();
    }

    public function testInstantiation()
    {
        $privateKey = new EC(ECCurveName::secp256r1);
        $this->assertInstanceOf(EC::class, $privateKey);
    }

    public function testGenerateKey()
    {
        $privateKey = new EC(ECCurveName::secp256r1);
        $publicKey = $privateKey->generate();
        $this->assertInstanceOf(EvpPKey::class, $publicKey);
    }

    public function testPublicKey()
    {
        $privateKey = new EC(ECCurveName::secp256r1);
        $privateKey->generate();
        $publicKey = $privateKey->getPKey();
        $this->assertInstanceOf(CData::class, $publicKey->getPkey());
    }
}
