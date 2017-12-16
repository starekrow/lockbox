<?php

namespace starekrow\Lockbox\tests;

use PHPUnit\Framework\TestCase;
use starekrow\Lockbox\Vault;

/**
 * @coversNothing
 */
class VaultTest extends TestCase
{
    public $dir;

    public static function tearDownAfterClass()
    {
        $dir = __DIR__ . '/testvault';
        if (is_dir($dir)) {
            foreach (glob($dir . '/*') as $file) {
                @unlink($file);
            }
            @rmdir($dir);
        }
    }

    public function setUp()
    {
        $this->dir = __DIR__ . '/testvault';
    }

    public function testConstruct()
    {
        $vault = new Vault($this->dir);

        $this->assertInstanceOf(Vault::class, $vault);
    }

    public function testOpenMissingVault()
    {
        $vault = new Vault($this->dir);

        $this->assertFalse($vault->open('test'));
    }

    public function testCreate()
    {
        $this->assertFileNotExists($this->dir, "vault shouldn't be here");

        $vault = new Vault($this->dir);

        $this->assertTrue($vault->createVault('test'), 'failed to create');

        $this->assertTrue(is_dir($this->dir), 'no vault after create');
    }

    public function testDestroy()
    {
        $vault = new Vault($this->dir);
        $vault->DestroyVault();

        $this->assertFalse(is_dir($this->dir));
    }

    public function testOpen()
    {
        $vault = new Vault($this->dir);
        $vault->createVault('blah');

        $vault2 = new Vault($this->dir);

        $this->assertTrue($vault2->open('blah'));

        $vault2->destroyVault();
    }

    public function testClose()
    {
        $vault = new Vault($this->dir);
        $vault->createVault('blah');
        $vault->close();

        $vault2 = new Vault($this->dir);

        $this->assertTrue($vault2->open('blah'));

        $vault2->destroyVault();
    }

    public function testPutAndGet()
    {
        $vault = new Vault($this->dir);
        $vault->createVault('foobar');
        $vault->put('test1', 'This is a test.');
        $got = $vault->get('test1');

        $this->assertSame('This is a test.', $got, 'original vault');

        $vault->Close();

        $vault2 = new Vault($this->dir);
        $vault2->open('foobar');
        $got = $vault2->get('test1');

        $this->assertSame('This is a test.', $got, 'after re-open');

        $vault2->destroyVault();
    }

    public function testChangePassword()
    {
        $vault = new Vault($this->dir);
        $vault->createVault('foobar');
        $vault->put('test1', 'This is a test.');
        $vault->close();

        $vault2 = new Vault($this->dir);

        $this->assertFalse($vault2->open('other'), 'Opened with wrong passphrase');
        $this->assertTrue($vault2->open('foobar'), 'Could not re-open');

        $vault2->changePassphrase('gobbledy');
        $vault2->put('test2', 'Another test');
        $vault2->close();

        $v3 = new Vault($this->dir);
        $this->assertTrue($v3->open('gobbledy'), 'open after key change');
        $this->assertSame('This is a test.', $v3->get('test1'), 'val1');
        $this->assertSame('Another test', $v3->get('test2'), 'val2');
        $v3->destroyVault();
    }

    public function testRotateMasterKey()
    {
        $vault = new Vault($this->dir);
        $vault->createVault('foobar');
        $vault->put('test1', 'This is a test.');
        $vault->close();

        $vault2 = new Vault($this->dir);
        $this->assertTrue($vault2->open('foobar'), 'Could not re-open');

        $vault2->rotateMasterKey('foobar');
        $vault2->put('test2', 'Another test');
        $vault2->close();

        $v3 = new Vault($this->dir);

        $this->assertTrue($v3->open('foobar'), 'open after key rotate');
        $this->assertSame('This is a test.', $v3->get('test1'), 'val1');
        $this->assertSame('Another test', $v3->get('test2'), 'val2');

        $v3->destroyVault();
    }
}
