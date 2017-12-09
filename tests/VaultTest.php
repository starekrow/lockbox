<?php

namespace starekrow\Lockbox\tests;

use PHPUnit\Framework\TestCase;
use starekrow\Lockbox\Vault;

class VaultTest extends TestCase
{
    public $dir;

    public function setUp()
    {
        $this->dir = __DIR__.'/testvault';
    }

    public function testConstruct()
    {
        $vault = new Vault($this->dir);

        $this->assertInstanceOf(Vault::class, $vault);
    }

    public function testOpenMissingVault()
    {
        $vault = new Vault($this->dir);

        $this->assertFalse($vault->Open('test'));
    }

    public function testCreate()
    {
        $this->assertFileNotExists($this->dir, "vault shouldn't be here");

        $vault = new Vault($this->dir);

        $this->assertTrue($vault->CreateVault('test'), 'failed to create');

        $this->assertDirectoryExists($this->dir, 'no vault after create');
    }

    public function testDestroy()
    {
        $vault = new Vault($this->dir);
        $vault->DestroyVault();

        $this->assertDirectoryNotExists($this->dir);
    }

    public function testOpen()
    {
        $vault = new Vault($this->dir);
        $vault->CreateVault('blah');

        $vault2 = new Vault($this->dir);

        $this->assertTrue($vault2->Open('blah'));

        $vault2->DestroyVault();
    }

    public function testClose()
    {
        $vault = new Vault($this->dir);
        $vault->CreateVault('blah');
        $vault->Close();

        $vault2 = new Vault($this->dir);

        $this->assertTrue($vault2->Open('blah'));

        $vault2->DestroyVault();
    }

    public function testPutAndGet()
    {
        $vault = new Vault($this->dir);
        $vault->CreateVault('foobar');
        $vault->Put('test1', 'This is a test.');
        $got = $vault->Get('test1');

        $this->assertEquals('This is a test.', $got, 'original vault');

        $vault->Close();

        $vault2 = new Vault($this->dir);
        $vault2->Open('foobar');
        $got = $vault2->Get('test1');

        $this->assertEquals('This is a test.', $got, 'after re-open');

        $vault2->DestroyVault();
    }

    public function testChangePassword()
    {
        $vault = new Vault($this->dir);
        $vault->CreateVault('foobar');
        $vault->Put('test1', 'This is a test.');
        $vault->Close();

        $vault2 = new Vault($this->dir);

        $this->assertFalse($vault2->Open('other'), 'Opened with wrong passphrase');
        $this->assertTrue($vault2->Open('foobar'), 'Could not re-open');

        $vault2->ChangePassphrase('gobbledy');
        $vault2->Put('test2', 'Another test');
        $vault2->Close();

        $v3 = new Vault($this->dir);
        $this->assertTrue($v3->Open('gobbledy'), 'open after key change');
        $this->assertEquals('This is a test.', $v3->Get('test1'), 'val1');
        $this->assertEquals('Another test', $v3->Get('test2'), 'val2');
        $v3->DestroyVault();
    }

    public function testRotateMasterKey()
    {
        $vault = new Vault($this->dir);
        $vault->CreateVault('foobar');
        $vault->Put('test1', 'This is a test.');
        $vault->Close();

        $vault2 = new Vault($this->dir);
        $this->assertTrue($vault2->Open('foobar'), 'Could not re-open');

        $vault2->RotateMasterKey('foobar');
        $vault2->Put('test2', 'Another test');
        $vault2->Close();

        $v3 = new Vault($this->dir);

        $this->assertTrue($v3->Open('foobar'), 'open after key rotate');
        $this->assertEquals('This is a test.', $v3->Get('test1'), 'val1');
        $this->assertEquals('Another test', $v3->Get('test2'), 'val2');

        $v3->DestroyVault();
    }
}
