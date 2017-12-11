<?php

namespace starekrow\Lockbox\tests;

use PHPUnit\Framework\TestCase;
use starekrow\Lockbox\Crypto;

class CryptoTest extends TestCase
{
    public function testAutoload()
    {
        $h = bin2hex( Crypto::hash( "sha1", "blah" ) );
        $want = "5bf1fd927dfb8679496a2e6cf00cbe50c1c87145";
        $this->assertEquals($h, $want, 'Wrong hash');
    }

    public function testWrongDriver()
    {
        $this->assertEquals( Crypto::init( "no_such_driver" ), false );
        try {
            Crypto::Random(5);
        } catch( \Exception $e ) {
            return;
        }
        $this->fail();
    }


    public function testUseBuiltin()
    {
        $this->assertNotEquals( Crypto::init( "builtin" ), false );
    }

    public function testUseOpenssl()
    {
        $this->assertNotEquals( Crypto::init( "openssl" ), false );
    }

    public function testResetToAutoloader()
    {
        $this->assertNotEquals( Crypto::init( "loader" ), false );
    }
}
