<?php

namespace starekrow\Lockbox\tests;

use PHPUnit\Framework\TestCase;
use starekrow\Lockbox\Crypto;

/**
 * @coversNothing
 */
class CryptoTest extends TestCase
{
    public function testAutoload()
    {
        $h = bin2hex(Crypto::hash("sha1", "blah"));
        $want = "5bf1fd927dfb8679496a2e6cf00cbe50c1c87145";
        $this->assertSame($h, $want, 'Wrong hash');
    }

    public function testWrongDriver()
    {
        $this->assertSame(Crypto::init("no_such_driver"), false);

        try {
            Crypto::Random(5);
        } catch (\Exception $e) {
            return;
        }
        $this->fail();
    }

    public function testUseBuiltin()
    {
        $this->assertNotSame(Crypto::init("builtin"), false);
    }

    public function testUseOpenssl()
    {
        $this->assertNotSame(Crypto::init("openssl"), false);
    }

    public function testOpenssl_AES128CBC()
    {
        Crypto::init("openssl");
        $key = hex2bin("d7397beb86bc85d590fc0b8c53c6188f");
        $iv = hex2bin("b0aefb01e733b0e2baf44b4ab77b5870");
        $msg = hex2bin("999689c32050125dda7250c9c9aae0ec");
        $ct = Crypto::encrypt("AES-128-CBC", $key, $iv, $msg);
        $this->assertSame(
            "2af8f5de48e24ae249696b8685b4b57170626116e4a159922dc408ca31ee5ee9",
            bin2hex($ct)
        );
    }

    public function testOpenssl_AES128CFB()
    {
        Crypto::init("openssl");
        $key = hex2bin("d7397beb86bc85d590fc0b8c53c6188f");
        $iv = hex2bin("b0aefb01e733b0e2baf44b4ab77b5870");
        $msg = hex2bin("999689c32050125dda7250c9c9aae0ec");
        $ct = Crypto::encrypt("AES-128-CFB", $key, $iv, $msg);
        $this->assertSame(
            "7fec0d24d21c3edbd9abc0359b6b1c89",
            bin2hex($ct)
        );
    }

    public function testOpenssl_AES128ECB()
    {
        Crypto::init("openssl");
        // one of the NIST test vectors
        $key = hex2bin("139a35422f1d61de3c91787fe0507afd");
        $iv = null;
        $msg = hex2bin("b9145a768b7dc489a096b546f43b231f");
        $ct = Crypto::encrypt("AES-128-ECB", $key, $iv, $msg);
        $this->assertSame(
            "0da1b56ba11c1a5500e95583c0eac913a9ed2204e460199a52bea0433523f504",
            bin2hex($ct)
        );
    }

    public function testResetToAutoloader()
    {
        $this->assertNotSame(Crypto::init("loader"), false);
    }
}
