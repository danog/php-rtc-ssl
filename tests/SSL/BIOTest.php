<?php

namespace Tests\Webrtc\SSL\SSL;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use Webrtc\SSL\Enum\BioMethod;
use Webrtc\SSL\OpenSSL;
use Webrtc\SSL\SSL\BIO;

#[UsesClass(OpenSSL::class)]
#[CoversClass(BIO::class)]
class BIOTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        OpenSSL::init();
    }

    public function testBioWriteRead()
    {
        $bio = new BIO(BioMethod::s_mem, BioMethod::s_mem);
        $bio->setBufferSize(1500);
        $bio->write('Hello ');
        $bio->write('World');
        $bio->write('!');

        $this->assertEquals('Hello World!', $bio->read(true));
    }

    public function testBioReadNull()
    {
        $bio = new BIO(BioMethod::s_mem, BioMethod::s_mem);
        $bio->setBufferSize(1500);
        $this->assertNull($bio->read());
    }
}
