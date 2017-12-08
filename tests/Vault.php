<?php
namespace Lockbox;

require_once __DIR__ . "/TestFramework.php";
require_once __DIR__ . "/../CryptoKey.php";
require_once __DIR__ . "/../Secret.php";
require_once __DIR__ . "/../Vault.php";


class test_CryptoKey extends \TestFramework
{
	public $dir;
	function t00_Prepare()
	{
		$this->dir = __DIR__ . "/testvault";
		if (is_dir( $this->dir )) {
			$this->Check( self::delTree($this->dir, "cannot clean old vault"));
		}
	}
	function t01_Construct()
	{
		$v = new Vault( $this->dir );
	}
	function t01_OpenMissingVault()
	{
		$v = new Vault( $this->dir );
		return !$v->Open( "test" );
	}
	function t02_Create()
	{
		$this->Check( !file_exists( $this->dir ), "vault shouldn't be here" );
		$v = new Vault( $this->dir );
		$this->Check( $v->CreateVault( "test" ), "failed to create" );
		$this->Check( is_dir( $this->dir ), "no vault after create" );
	}
	function t03_Destroy()
	{
		$v = new Vault( $this->dir );
		$v->DestroyVault();
		return !is_dir( $this->dir );
	}
	function t04_Open()
	{
		$v = new Vault( $this->dir );
		$v->CreateVault( "blah" );

		$v2 = new Vault( $this->dir );
		$this->Check( $v2->Open( "blah" ) );
		$v2->DestroyVault();
	}
	function t05_Close()
	{
		$v = new Vault( $this->dir );
		$v->CreateVault( "blah" );
		$v->Close();

		$v2 = new Vault( $this->dir );
		$this->Check( $v2->Open( "blah" ) );
		$v2->DestroyVault();
	}

	function t30_PutAndGet()
	{
		$v = new Vault( $this->dir );
		$v->CreateVault( "foobar" );
		$v->Put( "test1", "This is a test." );
		$got = $v->Get( "test1" );
		$this->Check( $got === "This is a test.", "original vault" );
		$v->Close();

		$v2 = new Vault( $this->dir );
		$v2->Open( "foobar" );
		$got = $v2->Get( "test1" );
		$this->Check( $got === "This is a test.", "after re-open" );
		$v2->DestroyVault();
	}

	function t40_ChangePassword()
	{
		$v = new Vault( $this->dir );
		$v->CreateVault( "foobar" );
		$v->Put( "test1", "This is a test." );
		$v->Close();

		$v2 = new Vault( $this->dir );
		$this->Check( !$v2->Open( "other" ), "Opened with wrong passphrase" );
		$this->Check( $v2->Open( "foobar" ), "Could not re-open" );
		$v2->ChangePassphrase( "gobbledy" );
		$v2->Put( "test2", "Another test" );
		$v2->Close();

		$v3 = new Vault( $this->dir );
		$this->Check( $v3->Open( "gobbledy" ), "open after key change" );
		$this->Check( $v3->Get( "test1" ) === "This is a test.", "val1" );
		$this->Check( $v3->Get( "test2" ) === "Another test", "val2" );
		$v3->DestroyVault();
	}
	function t41_RotateMasterKey()
	{
		$v = new Vault( $this->dir );
		$v->CreateVault( "foobar" );
		$v->Put( "test1", "This is a test." );
		$v->Close();

		$v2 = new Vault( $this->dir );
		$this->Check( $v2->Open( "foobar" ), "Could not re-open" );
		$v2->RotateMasterKey( "foobar" );
		$v2->Put( "test2", "Another test" );
		$v2->Close();

		$v3 = new Vault( $this->dir );
		$this->Check( $v3->Open( "foobar" ), "open after key rotate" );
		$this->Check( $v3->Get( "test1" ) === "This is a test.", "val1" );
		$this->Check( $v3->Get( "test2" ) === "Another test", "val2" );
		$v3->DestroyVault();
	}

	// from PHP.net
	public static function delTree($dir)
	{
		$files = array_diff( scandir($dir), array('.','..') );
	    foreach ($files as $file) {
	    	if (is_dir( "$dir/$file" )) {
	    		self::delTree( "$dir/$file" );
	    	} else {
	    		unlink( "$dir/$file" );
	    	}
	    }
	    return rmdir($dir);
	}

}

(new test_CryptoKey())->RunAllTests();
