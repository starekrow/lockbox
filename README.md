# Lockbox

Lockbox provides an interface for working with encrypted secret values. Each
value can be locked with one or more keys, making some kinds of key management
much easier than usual.

The default encryption is 128-bit AES.

There are three classes provided:

  * `Secret` - Storage and handling of secret values. Converts secrets to and
    from a printable representation, and manages lockboxes.
  * `CryptoKey` - Storage and services for cryptographic keys. Handles simple 
	encryption, decryption and converts keys to and from a printable 
	representation. Provides for cipher selection.
  * `Vault` - Manages an on-disk store of multiple secrets, locked with a 
    single master key. Also provides passphrase management and key rotation.

### Using Lockbox

Some example code:

	use Lockbox\Secret;
	use Lockbox\CryptoKey;

	$s = new Secret( "Sooper seekrit text" );
	$k = new CryptoKey( "youwillneverguessthis" );
	$s->AddLockbox( $k );

	echo "Secret:\n" . $s->Export() . "\n";
	echo "Key: " . $k->Export() . "\n";

	file_put_contents( "secret.txt", $s->Export() );
	file_put_contents( "key.txt", $k->Export() );

	// ...

	$k = CryptoKey::Import( file_get_contents( "key.txt" ) );
	$s = Secret::Import( file_get_contents( "secret.txt" ) );
	$s->Unlock( $k );
	echo $s->Read();

The corresponding output (the data key and ID are random each time):

	Secret:
	{
	    "locks": {
	        "5e2ebf46-26be-430e-bb6a-688e56943b08": "YZ1mbdLDxKihdXY
	t9h0C8zO0asoB55hw1Nn4QCQ1bS1Bl34A38ZHUP/ly8qlT+iclB6uRwAYt9gEBX9
	ADSWrACa97hlGrehpz7yLkEns9LT5yN49bteWVxg3To2wAfrVg/Pk8cyJqg0YbIg
	yShXQx5N6wBEstcRv2bzrwHx8FBeeA9c422R0T+HQ1ki6VOf2K7CJxiLDIAnRdZa
	nHzHq4A=="
	    },
	    "data": "zGREMJhcAT3vOxbRymvZkoeSHlR8EQESoOfpJJvgqSuxJIz5bAM
	g4eVph+Gf3KXkVa1baZSaX4dwYbSIWWm1z31ygCAEvrWZc8kzRFnFKqk="
	}
	Key: k0|5e2ebf46-26be-430e-bb6a-688e56943b08|QUVTLTEyOC1DQkM=|eW
	91d2lsbG5ldmVyZ3Vlc3N0aGlz
	Sooper seekrit text


### How it Works

Each secret value is stored in three parts:

  * The value itself is a binary string
  * A random 256-bit *internal key* is used to encrypt the value
  * One or more *lockboxes* is attached

The *internal key* is never used directly. Instead, you add a *lockbox* to the
secret. This stores the internal key encrypted with a passphrase (supplied by
you).

This arrangement has the following interesting properties:

  * The value can be decrypted with multiple, independent passphrases
  * A lockbox can be removed *without* decrypting the secret value.
  * A lockbox can only be added by someone who can decrypt the secret.

### Vaults

The provided `Vault` class manages a collection of secrets on-disk. You provide
a directory for the vault to occupy, and the master key and secrets are written
to individual files within that directory.

When using a vault, all the key and secret management is handled for you; you
just provide the passphrase when creating or opening the vault, and then put
values into the vault or get them from it.

The `Vault` class provides for changing the passphrase used to encrypt the 
master key and rotating the master key itself in each of the secrets in the 
vault. 

### Using Vaults

Some example code:

	$v = new Lockbox\Vault( "./secrets" );
	$v->CreateVault( "CorrectHorseBatteryStaple" );
	$v->Put( "test1", "This is a test." );
	$v->Close();

	// ...

	$v = new Lockbox\Vault( "./secrets" );
	$v->Open( "CorrectHorseBatteryStaple" );
	$got = $v->Get( "test1" );
	echo $got;						// prints "This is a test."

### Exposure Risks

This being PHP, there's no way (barring extensions) to actually scrub the 
contents of RAM. It might in fact not even be useful to do so anyway, due to 
other information leaks allowed by many OS configurations. In-process damage
(e.g. Heartbleed) might also defeat such measures. The following steps 
are taken to try to minimize the exposure risk:

  * Secrets can be loaded without supplying a key at all. This leaves just the
    encrypted text and the encrypted lockboxes in RAM. So you can prospectively
    load secrets and only decrypt them if needed. This also allows removing a
    lockbox from a secret without ever supplying the key.

  * Unlocking a secret does not automatically decrypt the value. The internal 
    key *is*, however, stored - in the clear - in RAM after unlocking. This 
    provides for the case where you want to add a lockbox to a secret but do
    not want to needlessly expose the unencrypted value in RAM.

  * Vaults only load secret values from disk as they are requested.

  * The passphrase used to decrypt a `Vault` master key is *not* retained by
    the `Vault` instance. Though, again, the master key itself *is* stored
    in the clear.

  * Both `Secret` and `Vault` provide a `Close()` method that immediately 
    detaches stored keys and plaintext values. `CryptoKey` provides a `Shred()`
    method that detaches the key data and id.

