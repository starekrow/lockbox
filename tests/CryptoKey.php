<?php
namespace starekrow\Lockbox\tests;

use starekrow\Lockbox\CryptoKey;
use starekrow\Lockbox\Secret;
use starekrow\Lockbox\Vault;

require_once __DIR__ . "/TestFramework.php";

class test_CryptoKey extends TestFramework
{
	function t00_Construct()
	{
		$k = new CryptoKey();
	}
	function t01_ConstructExplicit()
	{
		$k = new CryptoKey( "foobar", "test" );
		$this->Check( $k->id == "test", "Missing id" );
	}
	function t30_Export()
	{
		$k = new CryptoKey( "foobar", "test" );
		$t = $k->Export();
		return $t == "k0|test|QUVTLTEyOC1DQkM=|Zm9vYmFy";
	}
	function t30_Import()
	{
		$kt = "k0|test|QUVTLTEyOC1DQkM=|Zm9vYmFy";
		$k = CryptoKey::Import( $kt );
		$this->check( $k, "import failure" );
		$this->check( $k->id == "test", "id mismatch" );
	}
	function t50_EncryptDecrypt()
	{
		$k = new CryptoKey();
		$msg = "Hello, Dave.";
		$enc = $k->Lock( $msg );
		$this->check( $enc, "Encryption failed" );
		$this->check( $enc != $msg, "Encryption returned plaintext" );
		$dec = $k->Unlock( $enc );
		return $dec == $msg;
	}

}

(new test_CryptoKey())->RunAllTests();
