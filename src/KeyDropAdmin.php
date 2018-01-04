<?php
/**
 * Copyright (C) 2017 David O'Riva. MIT License.
 * Original at: https://github.com/starekrow/lockbox
 */

namespace starekrow\Lockbox;

/**
 * KeyDrop - Secure remote secret storage and syncronization
 *
 * KeyDrop implements a system for distributing and retrieving keys 
 * and secret values in a manner that is resistant to eavesdropping and
 * some kinds of server compromise.
 *
 * KeyDrop is usually used in a client/server model.
 * Each client is assigned an ID, a vault key, a client key and a shared key. 
 * The client key is stored in the clear on the client. The vault key is 
 * encrypted with the
 * client key and stored on the KeyDrop server. The vault itself is also stored
 * on the KeyDrop server. The shared key is stored in the clear on both sides, 
 * and is only used to authenticate communications.
 * 
 * There is also a provision for restricting access to
 * the encrypted vault and vault key by source IP.
 *
 * You should arrange for the client to query the server for the vault key and
 * then retain that key in RAM. The client should also be able to query the 
 * server for any changes to the vault and apply those changes to its cached 
 * copy.
 * 
 * This means that to compromise any of the vault contents, an attacker has to 
 * either compromise a running client, or acquire a filesystem image from both
 * the KeyDrop server *and* the client they are interested in.
 * 
 * This class has all the functions needed to implement both the client and 
 * the server. See KeyDropMemcache for an implementation of RAM caching of the
 * vault key using a local memcache daemon.
 *
 * A third set of functions is available to manage a keyring of 
 * vault keys. This can be used to apply updates to the secrets stored on 
 * the KeyDrop server for propagation to the appropriate client(s).
 *
 * ### Queries
 *
 * KeyDrop uses a consistent, generic query structure to aid in sending and
 * receiving the queries using your preferred transport mechanism. This also 
 * eases signing and validating the queries. The query is a set of key/value
 * pairs, each key and each value being a 7-bit safe ASCII string. Furthermore, 
 * keys may not contain the "=" character, and neither keys nor values may 
 * contain control characters other than TAB.
 * 
 * The response to a query follows the same rules for composition as a query, 
 * and responses generally must be signed as well.
 * 
 * Any signed query will include a "auth_time" field and a "auth_mac" 
 * field. Authentication requires that the tiemstamp be within 
 * 15 minutes of current UTC, to limit the scope for replays. The MAC used is
 * a SHA-256 HMAC of a canonical form of the query.
 * 
 * ### Keyrings
 *
 * A *keyring* stores various client keys. Each client's information is stored
 * independently, and locked with the keys of one or more users. Any user with
 * access to a given client's keys has the following capabilities:
 *
 *   * Encrypt a new secret value for a client
 *   * Update the KeyDrop server's copy of the client's vault
 *   * Grant these abilities to another user
 *
 * ### 
 * 
 * to store a keyring on a computer that is publicly available on the internet.
 * The preferred
 *
 * A solid, simple use model for KeyDrop might look like this:
 *
 *   * A group of servers that require secret value management is identified.
 *     This is the set of *KeyDrop clients*, or just "clients".
 *
 *   * Another server, which can be reached by all of the KeyDrop clients, is
 *     created. This is the *KeyDrop server*.
 *
 *   * A group of people and/or tools that are allowed to alter the secret 
 *     values for one or more KeyDrop clients is identified. This is the set of 
 *     *KeyDrop users*, or just "users".
 *
 * To get started, install Lockbox on the KeyDrop server and arrange to make
 * queries to it from the outside. An example is provided in "tools/keydropsrv".
 * It is necessary to assign a client ID and shared key to the KeyDrop server
 * before it can receive any queries.
 * Any user with access to these is allowed to create and delete clients 
 * within the KeyDrop server. They do not automatically obtain the ability to 
 * interact with the secret values of any given client, though.
 *
 * Then, create a new keyring (`createKeyring()`) on some system that is at 
 * least nominally protected from the internet (a development system behind a 
 * NATted firewall, for example). Create a new user (`addKeyringUser()`) named 
 * "admin" or some such. With that user's key, you can use `setKeyringValue`) 
 * to save the KeyDrop server's shared key.
 *
 * Now you can create client vaults and push them out to the KeyDrop server.
 * If needed, create the user that will have primary responsibility for the 
 * client. The "admin" user should use `pushNewClient()` to actually create the
 * client, and `setKeyringValue()` to save the resulting keys.
 *
 * 
 * 
 * 
 *
 * The user that creates a new client becomes the owner of that client, and has
 * the power to grant full client control to other users. 
 *
 * If you wish, you can add another layer of permissions that distinguish 
 * 
 *   * A server is created which can be connected to by all the is designated as the 
 *  Entities that are allowed to make changes to the 
 *   Each developer is assigned a *developer name* and a *developer key*. This is a CryptoKey 
 *
 * #### Keyring Queries
 *
 * 
 * ### Architecture
 *
 * There's actually very little difference between KeyDrop servers, clients and
 * users. Each has some level of access to a shared pool of structured secrets 
 * that can be synchronized in whole or in part.
 *
 * An item can be either a Secret or a Vault. Each item has three keys 
 * associated with it:
 *
 *   * The "share" key allows the item to be shared in its encrypted form.
 *   * The "use" key allows the item to be read or written. It can unlock the 
 *     Secret or act as the master key for the vault.
 *

Low-level API:

 * pullItem - pull the latest (encrypted) copy of the item
 * pushItem - push the current (encrypted) value of the item
 * readItem - read the item's value - requires item key
 * writeItem - update the item's value - requires item key

Clients can only pull from remote and read from local. Theoretically they could
write to local as well, but any changes could be overridden at any time by a 
remote pull.

Clients have three local values: A client ID (aka user name), a pull key that 
can pull their vault key and their vault, and a local key that can decrypt the
vault key.

It is possible to grant "share" privileges to a user. This is how developers
are enabled to update the secret vaults for a KeyDrop client. In fact, share
privileges can be chained to prevent secret values from landing *anywhere* in
an unencrypted form. This works as follows:

 * A local server is set up to hold all of the secrets for a small business. 
   Call it the "keeper". Stick it behind a firewall and a NAT layer.
 * The keeper is initially set up with an "admin" user that has every privilege
   imaginable. At this point you should detach the keyboard and put it in a 
   locked room. The same effect can be simulated in the cloud by 
 * 

Any user can create a new secret:
  * Encrypt with user key
    * use comm key to pull encrypted user key
    * use local key to decrypt user key
    * encrypt secret
  * Save to local vault
  * Use comm key to push secret to user's vault on keeper

To share a secret with another user:
  * Unlock secret
    * use comm key to pull encrypted user key
    * use local key to decrypt user key
    * use user key to unlock secret
  * Encrypt internal key with other user's public key
  * Issue share request
    * use comm key to encrypt query with internal key, other ID, share request
    * Send to keeper
    * Keeper adds to user's pending share list
  * Target pulls share list
  * 

To share a secret with another user:
  * Request sharing key from keeper
    * Keeper encrypts sharing key with user comm key
    * Keeper encrypts sharing key with other user's comm key
  * Keeper returns encrypted sharing key
  * User re-encrypts secret with sharing key
  * User returns encrypted sharing key to keeper
  * Keeper 

Note that a user's "push" key can be used to 






Privileges:

 * 

 their locally obtained client ID and client key to 

Users 

Pass 3
======

A KeyDrop organizes secrets and keys by client ID and name.

Each client of the KeyDrop gets an ID and a message key. The message key
is used to encrypt messages each way, also providing authentication of the
message and reply.

Supported queries:

  * Create/update/read/remove secret
  * Enumerate secrets
  * Read all secrets for a client
  * Create/remove client

There is additional built-in support for two client roles: Administrator and 
worker.

### Administrator Role

The administrator uses local storage to house a passphrase-protected keyring.
This keyring contains various keys for other clients of the KeyDrop server.
Administrators can create or remove other clients.

### Worker Role

A worker client maintains a local Vault with a copy of all the secrets from the
KeyDrop server. Also, workers are expected to use a two-part vault key, with 
a "vaultkey" secret stored on the KeyDrop server and a "clientkey" key stored
locally. The worker should take precautions to ensure that the vaultkey secret
is never stored on the local filesystem.

When starting, a worker should query the KeyDrop server for the full list of
secrets. Most of these can be stored on disk locally, but the "vaultkey" should
be tucked away in RAM only. To open the vault, the worker must decrypt the
vaultkey with its clientkey and use the result to open the vault.

So, the worker has three values that are required to get it started:

  * client ID
  * message key
  * vault key decryptor

Those values, along with the decrypted vault key, are stored in the 
administrator's keyring for that worker.

### Rationale

This system has the following advantages:

  * Administrators do not actually store any secret values locally
  * The KeyDrop server does not have enough information to decrypt any of the
    secrets stored on it.
  * Each worker only has access to the secrets designated for it.
  * An image of the worker's filesystem does not include the key needed to 
    decrypt the worker's local vault.


 *
 * @package starekrow\Lockbox
 */
class KeyDropAdmin
{
    protected $vault;

    protected function runQuery( $query )
    {

    }

    public function createWorker( );
    public function addClientSecret();
    

    /**
     *
     * The query should be sent to the KeyDrop server. The response string
     * should be passed through decodeResponse, at which point you will have
     * an array with element 0 being the "vaultKey" property and element 1
     * being the "secrets" property.
     * 
     * @return string An encoded query for the worker information 
     */
    public static function queryWorkerInfo($clientId, $messageKey)
    {
        $q = [
            "batch" => [
                [
                     "action" => "get"
                    ,"type" => "config"
                    ,"name" => "vaultKey"
                ],
                [
                     "action" => "dump"
                    ,"type" => "secrets"
                ]
            ]
        ];
        return encodeQuery($clientId, $q, $messageKey);
    }

    /**
     *
     */
    public static function adminCreateWorker($clientId, $messageKey, $name)
    {
        $msgKey = new CryptoKey();
        $vaultKey = Crypto::random(32);
        $clientKey = new CryptoKey();
        $encVaultKey = $clientKey->Lock( $vaultKey );
        $q = [
            "batch" => [
                [
                     "action" => "newClient"
                    ,"name" => "$name"
                ],
                [
                     "action" => "set"
                    ,"type" => "config"
                    ,"name" => "vaultKey"
                    ,"value" => $encVaultKey
                ],
                [
                     "action" => "set"
                    ,"type" => "config"
                    ,"name" => "messageKey"
                    ,"value" => $msgKey->export()
                ]
            ]
        ];
        return [
             "messageKey" => $msgKey->export()
            ,"clientKey" => $clientKey->export()
            ,"query" => encodeQuery($clientId, $q, $messageKey);
        ];
    }

    /**
     * getClientValue
     *
     * See setClientValue for some interesting values you can set
     *  
     *
     */
    public function getClientValue( $name )
    {

    }


    /**
     * setClientId
     *
     */
    public function setClientId( $clientId )
    {

    }

    /**
     * getClientId
     *
     */
    public function getClientId()
    {
    }


    /**
     * useVault - Sets the vault to use for subsequent calls
     *
     */
    public function useVault( $vault )
    {
    }

    /**
     * openKeyring
     *
     * A keyring stores a 
     *
     */
    public function openKeyring( $path, $passphrase )
    {
    }

    /**
     * getKeyringValue
     *
     */
    public function getKeyringValue( $clientId, $name )
    {
    }

    /**
     * setKeyringValue
     * 
     * Possible value names:
     *  vaultKey - actual vault key
     *  clientKey - actual client key
     *  sharedKey - actual shared key
     *  notes - secure text
     *
     */
    public function setKeyringValue( $clientId, $name, $value )
    {

    }

    /**
     * closeKeyring
     *
     */
    public function closeKeyring()
    {
    }

    /**
     * pushClientInfo
     *
     * Returns a query that will push new or updated client info to a KeyDrop
     * server.
     *
     * Client info includes the client ID, source ACL, encrypted vault key and
     * shared key.
     *
     */
    public function pushClientInfo()
    {

    }

    /**
     * pushClientSecret
     *
     * Returns a query that will push a new, updated or removed secret to a 
     * client vault on a KeyDrop server.
     *
     */
    public function pushClientSecret( $name, $secret )
    {

    }

    /**
     * create
     *
     */
    public static function create($path)
    {
        if (is_dir($path)) {
            return false;
        }
        mkdir($path, 0700, true);
        return new KeyDrop($path);
    }

    /**
     * __construct - Set up a new server or client instance
     *
     * @param array|stdclass $options  Settings for the instance
     * 
     */
    public function __construct($path)
    {
        if (!is_dir($path)) {
            throw new Exception( "No keydrop found at given path" );
        }
        $this->dataDir = $path;
        $this->clientCache = [];
    }
}
