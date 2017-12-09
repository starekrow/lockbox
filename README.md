# Lockbox

Lockbox is a simple, tiered system for working with cryptographic keys and 
encrypted data. It provides a set of easy-to-use interfaces that encourage
a "secure by default" design.

There are three primary concepts to Lockbox: *Keys*, *secrets* and *vaults*.
Keys are used for encryption or decryption of data. Secrets are data values 
that can be read or written using multiple keys. A vault is one way to store
a collection of secrets, that also comes with some built-in key management 
tools.

Interesting fact: The classes here were originally designed to support 
responsible handling of authentication tokens for server applications, to
ensure that the various passwords and API keys for production servers weren't 
just dumped in plain text into the file system. This is particularly important
for cloud servers, where access to the disk images is entirely out of the 
so-called "site owner's" control.

## Quick-Start

To encrypt some data:

```php
// CryptoKey defaults to AES-128-CBC encryption with a random key
$key = new CryptoKey();
$message = "You can't see me.";
$ciphertext = $key->Lock( $message );

file_put_contents( "key.txt", $key->Export() );
file_put_contents( "cipher.txt", $ciphertext );
```

To decrypt some encrypted data:

```php
$key = CryptoKey::Import( file_get_contents( "key.txt" ) );
$ciphertext = file_get_contents( "cipher.txt" );
$message = $key->Unlock( $ciphertext );
echo $message; 			// "You can't see me."
```

To use a specified key and a different cipher:

```php
$key = new CryptoKey( "ILikeCheese", null, "AES-256-ECB" );
$no_see_um = $key->Lock( "This text is safe." );
$see_um = $key->Unlock( $no_see_um );
```

> Note that if your key is not the expected length for the given cipher, PHP's
`openssl` extension will apply some default padding or cropping to your key
data. For interoperability with non-PHP crypto systems, be sure to specify the 
key at the proper length for your chosen cipher.

To encrypt some data (even structured data) so that it can be decrypted with 
more than one key:

```php
$s = new Secret( [ "my stuff" => "Sooper seekrit" ] );
$k = new CryptoKey( "correcthorsebatterystaple" );
$k2 = new CryptoKey( "ILikeCheese" );
$s->AddLockbox( $k );
$s->AddLockbox( $k2 );
file_put_contents( "secret.txt", $s->Export() );
file_put_contents( "key.txt", $k->Export() );
file_put_contents( "key2.txt", $k2->Export() );
```

To get that data back:

```php
$s = Secret::Import( file_get_contents( "secret.txt" ) );
$k = CryptoKey::Import( file_get_contents( "key.txt" ) );
$s->Unlock( $k );
$val = $s->Read();
echo $val["my stuff"]; 				// "Sooper seekrit"
```

Interestingly, `secret.txt` contains something like:

```json
{
    "locks": {
	"17e9c178-7a99-47ac-a422-5ec9a9e0a6e8": "2W2ElRE4S7xu93xx
cvIF7dubb+46YhgZKDS3Lnztc7YDL+Had4nNIRqZ03jzW8w1IaZtMAudFTQFLejVY
MwDeHnpHotBR5UBo0TZq4jgW2hetGbahLOpni3hhwbU9at8By34Dj53UfK84pXyOe
2RH90+b/vL9OLAD51hupsbI2TlKPjCsys8V3EhaIz0a57yCKhAyMarZkyklRKvFYv
bKw==",
	"0188b485-0937-4695-a0d6-5f968b286fc9": "Ugq4MuwOfvyKlREh
VJDFLuRR8U7O6y0e3KYD2Gllk4QC0EaC2MJDtJ9yCkePF49zsukgmjSpHvhAjg1ZN
3yWEOR8DE3kDY8rai9RC1LRRC0iK2nTg7DqCsvUV57nY1mG5MVpW8LXAirjRtCasj
2yJu1D1JY0U06hXpSDoVzaLSFqPoRoSAI231SwISgnqhLCUEt7L7LGwIt3voMehH6
wxg=="
    },
    "data": "+2uEgQ52VGOVvGu41umPhjurmqhoXHMqhbzoFeQuWs63rFQNVW9H
K3dlEddEyZfoe+lXT2M5MElUfdXF1vWZ8mLiorVkN8N+Waz6YeyZ3CePpYPNsZT9y
MCWAQNwnTjU"
}
```

And `key.txt` contains:

```
k0|17e9c178-7a99-47ac-a422-5ec9a9e0a6e8|QUVTLTEyOC1DQkM=|Y29ycmVj
dGhvcnNlYmF0dGVyeXN0YXBsZQ==
```

Create a vault and put a value into it:

```php
$v = new Lockbox\Vault( "./secrets" );
$v->CreateVault( "CorrectHorseBatteryStaple" );
$v->Put( "test1", "This is a test." );
$v->Close();
```

Open an existing vault and read a value from it:

```php
$v = new Lockbox\Vault( "./secrets" );
$v->Open( "CorrectHorseBatteryStaple" );
$got = $v->Get( "test1" );
echo $got;						// prints "This is a test."
```

## How it Works

Each tier of the interface adds capabilities:

  * `CryptoKey` handles basic encryption and decryption, and packages both the
    keys and the ciphertext for output, verification and decryption.
  * `Secret` is a managed, encrypted data value with lockbox-style key 
    handling.
  * A `Vault` is file-based storage for secrets, with a master key and some
    additional key management tools.

### CryptoKey

All of the actual encryption and decryption is done with `CryptoKey` instances. 
These bundle together the pieces - cipher type and key data, along with a 
unique key identifier to help with higher-level management - needed to 
successfully decrypt a previously encrypted message. They also produce 
representations of themselves and of the encrypted messages in tidy, 
ASCII-safe strings.

Think of a key as a complete encryption package: You use the key to lock 
plaintext (producing ciphertext) and to unlock ciphertext (producing plaintext).

A `CryptoKey` can be built with an (optional) passphrase, an (optional) id
string and an (optional) cipher specifier. Any parameter that isn't 
specified is filled with a reasonable default: A 256-bit random key, a 128-bit 
(well, 123-bit) random ID formatted as a GUID, and an AES-128-CBC cipher.

The output of a `Lock()` operation includes the IV used and an HMAC of the 
ciphertext, as well as the ciphertext itself. Those are then concatenated and 
base-64 encoded. The result can be easily verified and decrypted with 
`Unlock()`.

The keys themselves, along with the exact cipher used and the key identifier,
can be converted to a simple printable string representation with `Export()`
and read back in with `Import()`. 

### Secret

The `Secret` class provides a more extensive interface to handling a value that 
needs to be protected. Each secret consists of three parts:

  * The value itself is a binary string. Serialization from and to other data
    types is automatic.
  * A random 256-bit *internal key* is used to encrypt the value.
  * One or more *lockboxes* is attached.

The secret is created with any value, and can be locked (or unlocked) with one 
or more different keys, using a virtual lockbox model. In this model, the 
secret's value is encrypted with the internal key. However, the 
internal key is never saved directly, but is itself encrypted by the various 
lockbox keys you supply. This arrangement has the following interesting 
properties:

  * The value can be decrypted with multiple, independent passphrases
  * The value can be updated by anyone with a valid lockbox key. Other 
    key-holders will then see the updated value.
  * A lockbox can be removed *without* decrypting the value.
  * A lockbox can only be added by a valid key-holder.
  * A lockbox key cannot be used to learn anything about the other lockbox keys
    (except their public ID, which is in the clear anyway).

Like keys, secrets are rendered in an ASCII-safe printable package (in this
case, a JSON wrapper around some base-64 strings) with `Export()` and can be
reconstituted with `Import()`. `AddLockbox()` takes a key you supply and 
encrypts the internal key with it, adding the resulting virtual lockbox to the
secret. Additional management can be done with `RemoveLockbox()`, 
`HasLockbox()` and `ListLockboxes()`. 

`Unlock()` takes a key matching any lockbox and decrypts the internal key from 
the lockbox. `Lock()` just discards any saved copies of the internal key and 
decrypted value. 

If the secret has been unlocked, you can use `Read()` to get the value out of 
it, and `Update()` to change it.

### Vault

A `Vault` uses the properties of the `Secret` class to provide an encrypted
key-value store on disk that is as robust to interruption as the underlying 
file system. 

You supply the name of a directory for the vault, and the secrets are stored in 
individual files in that directory. A random 
*master key* is generated and used to encrypt each one. That
master key is itself encrypted with a passphrase, an arrangement that allows the
passphrase to be changed without changing the master key, and allows the master
key itself to be rotated in stages, no matter the size of the vault.

When using a vault, all the key and secret management is handled for you. Use
`CreateVault()` to set up a new vault (this will fail if a vault already 
exists in the chosen directory) or `Open()` to open an existing one. 
`VaultExists()` and `DestroyVault()` round out the vault management suite.
`Close()` forgets all keys and cached secrets without affecting the vault
on disk.

Manage values within the vault with `Put()`, `Get()`, `Has()`, `Remove()` and
`PerSecret()`.

You can change the passphrase used to encrypt the master key with 
`ChangePassphrase()`. This is a comparatively fast and safe operation, affecting
only one file. Rotate the master key itself with `RotateMasterKey()`.

## Exposure Risks

This being PHP, there's no way (barring extensions) to actually scrub the 
contents of RAM. It might in fact not even be useful to do so anyway, due to 
other information leaks (swap files) allowed by many OS configurations. 
In-process damage (e.g. Heartbleed) might also defeat such measures. The 
following steps are taken to try to minimize the exposure risk:

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

