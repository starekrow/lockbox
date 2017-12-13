<?php

namespace starekrow\Lockbox\tests;

use PHPUnit\Framework\TestCase;
use starekrow\Lockbox\CryptoKey;

class CryptoKeyTest extends TestCase
{
    public function testConstruct()
    {
        $cryptoKey = new CryptoKey();

        $this->assertInstanceOf(CryptoKey::class, $cryptoKey);
    }

    public function testConstructExplicit()
    {
        $cryptoKey = new CryptoKey('foobar', 'test');

        $this->assertEquals('test', $cryptoKey->id, 'Missing id');
    }

    public function testExport()
    {
        $cryptoKey = new CryptoKey('foobar', 'test');
        $result = $cryptoKey->export();

        $this->assertEquals('k1|test|QUVTLTEyOC1DQkM=|Zm9vYmFy|c2hhMjU2', $result);
    }

    public function testImport()
    {
        $kt = 'k0|test|QUVTLTEyOC1DQkM=|Zm9vYmFy';
        $cryptoKey = CryptoKey::import($kt);

        $this->assertInstanceOf(CryptoKey::class, $cryptoKey, 'import failure');
        $this->assertEquals('test', $cryptoKey->id, 'id mismatch');

        $kt = 'k1|test|QUVTLTEyOC1DQkM=|Zm9vYmFy|c2hhMjU2';
        $cryptoKey = CryptoKey::import($kt);

        $this->assertInstanceOf(CryptoKey::class, $cryptoKey, 'import failure');
        $this->assertEquals('test', $cryptoKey->id, 'id mismatch');
    }

    public function testEncryptDecrypt()
    {
        $cryptoKey = new CryptoKey();
        $msg = 'Hello, Dave.';
        $ciphertext = $cryptoKey->lock($msg);

        $this->assertInternalType('string', $ciphertext, 'Encryption failed');
        $this->assertNotEquals($msg, $ciphertext, 'Encryption returned plaintext');

        $dec = $cryptoKey->unlock($ciphertext);

        $this->assertEquals($msg, $dec);
    }
}
