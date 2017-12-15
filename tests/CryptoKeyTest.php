<?php

namespace starekrow\Lockbox\tests;

use PHPUnit\Framework\TestCase;
use starekrow\Lockbox\CryptoKey;

/**
 * @coversNothing
 */
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

        $this->assertSame('test', $cryptoKey->id, 'Missing id');
    }

    public function testExport()
    {
        $cryptoKey = new CryptoKey('foobar', 'test', null, null, 'random salt');
        $result = $cryptoKey->export();

        $this->assertSame('k1|test|QUVTLTEyOC1DQkM=|Zm9vYmFy|c2hhMjU2', $result);
    }

    public function testImport()
    {
        //tests k0 for backwards compatibility
        $kt = 'k0|test|QUVTLTEyOC1DQkM=|Zm9vYmFy';
        $cryptoKey = CryptoKey::import($kt);

        $this->assertInstanceOf(CryptoKey::class, $cryptoKey, 'import failure');
        $this->assertSame('test', $cryptoKey->id, 'id mismatch');

        //tests k1 (latest version)
        $kt = 'k1|test|QUVTLTEyOC1DQkM=|Zm9vYmFy|c2hhMjU2';
        $cryptoKey = CryptoKey::import($kt);

        $this->assertInstanceOf(CryptoKey::class, $cryptoKey, 'import failure');
        $this->assertSame('test', $cryptoKey->id, 'id mismatch');
    }

    public function testEncryptDecrypt()
    {
        $cryptoKey = new CryptoKey();
        $msg = 'Hello, Dave.';
        $ciphertext = $cryptoKey->lock($msg);

        $this->assertInternalType('string', $ciphertext, 'Encryption failed');
        $this->assertNotSame($msg, $ciphertext, 'Encryption returned plaintext');

        $dec = $cryptoKey->unlock($ciphertext);

        $this->assertSame($msg, $dec);
    }
}
