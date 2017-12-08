<?php /* Copyright (C) 2017 David O'Riva. MIT License.
       * Original at: https://github.com/starekrow/lockbox
       ********************************************************/
namespace Lockbox;

/*
================================================================================
Vault - Manage a storehouse of secret values

Given a directory, manages a set of secret values and master keys. The 
following operations are supported:

  * Put - Saves a secret value
  * Get - Loads a secret value
  * Has - Checks for the existence of a secret value
  * Remove - Removes a secret value
  * TODO: RotateMasterKey - Replace the master key with a new one
  * ChangePassphrase - Re-encode the vault's master key with a new passphrase
  * Open - Opens the vault
  * Close - Closes the vault
  * CreateVault - Creates a new vault
  * DestroyVault - Erases the vault. Optionally scrubs files.
  * VaultExists - Checks for the existence of the vault

================================================================================
*/
class Vault
{
	public $path;
	protected $activeDataKey;
	protected $dataKeys;
	protected $secrets;
	
	/*
	=====================
	LoadDataKeys
	=====================
	*/
	protected function LoadDataKeys( $masterKey )
	{
		$mks = @file_get_contents("$this->path/master.keys");
		if (!$mks) {
			return false;
		}
		$dk = Secret::Import( $mks );
		if (!$dk) {
			return false;
		}
		if (!$dk->Unlock( $masterKey )) {
			return false;
		}
		$this->dataKeys = [];
		$kl = $dk->Read();
		foreach ($kl as $id => $key) {
			if ($id == "active") {
				$this->activeDataKey = $key;
			} else {
				$this->dataKeys[ $id ] = CryptoKey::Import($key);
			}
		}
		return true;
	}

	/*
	=====================
	SaveDataKeys
	=====================
	*/
	protected function SaveDataKeys( $masterKey )
	{
		$kl = [];
		foreach ($this->dataKeys as $id => $key) {
			$kl[ $id ] = $key->Export();
		}
		$kl[ "active" ] = $this->activeDataKey;
		$dk = new Secret( $kl );
		$dk->AddLockbox( $masterKey );
		file_put_contents("$this->path/master.keys", $dk->Export());
		return true;
	}

	/*
	=====================
	PerSecret

	Execute a function for each secret in the vault.
	=====================
	*/
	public function PerSecret( $callback )
	{
		$d = opendir( $this->path );
		while ($d && ($fn = readdir( $d )) !== FALSE) {
			if (substr( $fn, -5 ) == ".data") {
				$callback( substr( $fn, 0, strlen( $fn ) - 5 ) );
			}
		}
		closedir( $d );
	}


	/*
	=====================
	Get
	=====================
	*/
	public function Get( $name )
	{
		if (empty( $this->secrets[ $name ] )) {
			$sf = @file_get_contents( "$this->path/$name.data" );
			if (!$sf) {
				return false;
			}
			$s = Secret::Import( $sf );
			if (!$s) {
				return false;
			}
			$this->secrets[ $name ] = $s;
		}
		$s = $this->secrets[ $name ];
		if (!$s->locked) {
			return $s->Read();
		}
		foreach ($this->dataKeys as $key) {
			if ($s->Unlock( $key )) {
				break;
			}
		}
		return $s->locked ? false : $s->Read();
	}

	/*
	=====================
	Has
	=====================
	*/
	public function Has( $name )
	{
		return file_exists( "$this->path/$name.data" );
	}

	/*
	=====================
	Put
	=====================
	*/
	public function Put( $name, $value )
	{
		if (!$this->activeDataKey) {
			return false;
		}
		if (!empty( $this->secrets[ $name ] )
		    && !$this->secrets[ $name ]->locked) {
			$did = $this->secrets[ $name ]->Update( $value );
			if (!$did) {
				return false;
			}
		} else {
			$this->secrets[ $name ] = new Secret( $value );
		}
		$this->secrets[ $name ]->AddLockbox( 
			$this->dataKeys[ $this->activeDataKey ] );
		$kd = $this->secrets[ $name ]->Export();
		file_put_contents( "$this->path/$name.data", $kd );
		return true;
	}

	/*
	=====================
	Remove
	=====================
	*/
	public function Remove( $name )
	{
		unset( $this->secrets[ $name ] );
		$this->DestroyFile( "$name.data", true );
	}

	/*
	=====================
	DestroyFile
	=====================
	*/
	protected function DestroyFile( $name, $scrub )
	{
		$fn = $this->path . "/" . $name;
		if (!$scrub) {
			unlink( $fn );
			return;
		}
		$s = filesize( $fn );
		$f = fopen( $fn, "rb+" );
		if (!$f) {
			unlink( $fn );
			return;
		}
		fseek( $f, 0, SEEK_SET );
		fwrite( $f, openssl_random_pseudo_bytes( $s ) );
		fclose( $f );
		unlink( $fn );
	}


	/*
	=====================
	RotateMasterKey

	Process is intended to eliminate possibility of catastrophic data loss 
	(but see WARNING below). Currently, the process is only protected against
	interruption (e.g. power loss, accidentally hitting ^C, etc). You should 
	not write to the vault at all while the rotation is taking place, and all 
	processes should reload the vault after rotation.

	All secrets are flushed from the Vault cache.

	This is the process followed:
	  * Add new data key to master key set
	  * Cycle through all secrets, unlocking with existing data key and 
	    then adding lockbox for new data key.
	  * Remove old data key from key store
	  * Any interruption of the process will leave the key store and secrets
	    in a recoverable state.
	  * If there are multiple data keys when the process starts, all existing
	    keys are tried for unlocking the secrets and then retired at the end. 

	## WARNING:

	> Currently, *you* are responsible for ensuring that this is the only
	process using this vault when you rotate the master key. Consider the
	following sequence of events:

	>		A opens vault
	>		A reads secret S1 from vault
	>		B opens vault and begins key rotation
	>		B completes key rotation
	>		A writes new secret S2 to vault 
	>		A updates secret S1 in vault
	>		B updates secret S3 in vault
	>		A reads secret S3 from vault

	> At this point, S1 and S2 are essentially destroyed because they are using
	a master key that doesn't exist on disk anymore. And A has failed to 
	decrypt S3.

	=====================
	*/
	public function RotateMasterKey( $passphrase )
	{
		if (!$this->activeDataKey) {
			return false;
		}
		$this->Close();
		$mk = new CryptoKey( $passphrase, "master" );
		$this->LoadDataKeys( $mk );

		$ndk = new CryptoKey();
		if (!empty( $this->dataKeys[ $ndk->id ] )) {
			throw new \Exception( "Vault data key GUID not unique" );
		}
		$this->dataKeys[ $ndk->id ] = $ndk;
		$this->SaveDataKeys( $mk );

		$this->PerSecret( function( $name ) use ($ndk) {
			$s = Secret::Import( 
				@file_get_contents( "$this->path/$name.data" )
			);
			if (!$s) {
				return;
			}
			foreach ($this->dataKeys as $key) {
				if ($key->id != $ndk->id && $s->Unlock( $key )) {
					break;
				}
			}
			if (!$s->locked) {
				$s->AddLockbox( $ndk );
				file_put_contents( "$this->path/$name.data", $s->Export() );
			}
		} );

		$this->activeDataKey = $ndk->id;
		$this->SaveDataKeys( $mk );

		$remove = array_diff( array_keys( $this->dataKeys ), [ $ndk->id ] );

		$this->PerSecret( function( $name ) use ($ndk,$remove) {
			$s = Secret::Import( 
				@file_get_contents( "$this->path/$name.data" )
			);
			if (!$s) {
				return;
			}
			if ($s->Unlock( $ndk )) {
				foreach ($remove as $id) {
					$s->RemoveLockbox( $id );
				}
				file_put_contents( "$this->path/$name.data", $s->Export() );
			}
		} );


		foreach ($remove as $id) {
			unset( $this->dataKeys[ $id ] );
		}
		$this->SaveDataKeys( $mk );
		$mk->Shred();
	}

	/*
	=====================
	ChangePassphrase

	Changes the passphrase for the current active master key. The vault must
	already be unlocked for this to succeed.
	=====================
	*/
	public function ChangePassphrase( $passphrase )
	{
		if (!$this->activeDataKey) {
			return false;
		}
		$mk = new CryptoKey( $passphrase, "master" );
		$this->SaveDataKeys( $mk );
		return true;
	}

	/*
	=====================
	DestroyVault

	Destroys the vault. There are three supported styles:

	* `fast` - just deletes the file containing the master key
	* `key` - overwrite the master key with random data, then delete it.
	* `complete` - overwrite all files with random data, then delete them.

	If no style is given, it defaults to `complete`.
	=====================
	*/
	public function DestroyVault( $style = null )
	{
		$scrub = true;

		switch ($style) {
		case "fast":
			$scrub = false;
		case "key":
			$this->DestroyFile( "master.keys", $scrub );
			break;

		case "complete":
		default:
			// destroy early
			$this->DestroyFile( "master.keys", $scrub );
			$this->PerSecret( [ $this, "Remove" ] );
			@rmdir( $this->path );
		}
	}

	/*
	=====================
	CreateVault

	Creates a new vault with a fresh master key. This will fail if the vault
	already exists.

	If the vault directory doesn't exist, it will be created with privileges
	restricting access to the current user.
	=====================
	*/
	public function CreateVault( $passphrase )
	{
		if (file_exists( "$this->path/master.keys" )) {
			return false;
		}
		$dk = new CryptoKey();

		$this->dataKeys = [];
		$this->dataKeys[ $dk->id ] = $dk;
		$this->activeDataKey = $dk->id;
		$this->secrets = [];

		$mk = new CryptoKey( $passphrase, "master" );

		if (!is_dir( $this->path )) {
			@mkdir( $this->path, 0700, true );
		}
		return $this->SaveDataKeys( $mk );
	}

	/*
	=====================
	VaultExists
	=====================
	*/
	public function VaultExists()
	{
		return file_exists( "$this->path/master.keys" );
	}

	/*
	=====================
	Open

	Opens the vault using the given master passphrase.
	=====================
	*/
	public function Open( $passphrase )
	{
		$mk = new CryptoKey( $passphrase, "master" );
		$did = $this->LoadDataKeys( $mk );
		if ($did) {
			return true;
		}
		return false;
	}

	/*
	=====================
	Close

	Closes the vault and forgets all keys and secrets.
	=====================
	*/
	public function Close()
	{
		$this->activeDataKey = null;
		$this->dataKeys = [];
		$this->secrets = [];
	}

	/*
	=====================
	__construct

	Sets up a Vault instance to operate at the given location. This does
	not actually create or open any files. Use Open() or Reset() as appropriate
	to start using the vault.
	=====================
	*/
	public function __construct( $path )
	{
		$this->path = $path;
		$this->dataKeys = [];
		$this->secrets = [];
	}
}
