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
 * @package starekrow\Lockbox
 */
class KeyDrop
{

    /**
     * signQuery
     *
     */
    public static function signQuery( $query, $sharedKey )
    {
    }

    /**
     * authenticateQuery
     *
     */
    public static function authenticateQuery( $query, $sharedKey )
    {
    }

    /**
     * queryVaultKey
     *
     */
    public function queryVaultKey()
    {
    }

    /**
     * queryVaultChanges
     *
     */
    public function queryVaultChanges()
    {
    }

    /**
     * getVaultChanges
     *
     */
    public function getVaultChanges()
    {
    }

    /**
     * handleQuery
     *
     * Handles a query sent to a KeyDrop server.
     *
     */
    public function handleQuery( $method, $data )
    {
    }

    /**
     * setClientValue
     *
     * Sets values in a KeyDrop server's client table.
     *
     * Handy values:
     *  sourceACL - array of acceptable IP addresses
     *  vaultKey - encrpyted vault key
     *  sharedKey - MAC key
     *
     */
    public function setClientValue( $name, $value )
    {
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
     */
    public function openKeyring( $passphrase )
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
     * Possible values:
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
     * setPushKey
     *
     * Assigns the key and client ID to use when signing push requests.
     *
     */
    public function setPushKey( $key, $id )
    {
    }

    /**
     * __construct - Set up a new server or client instance
     *
     * @param array|stdclass $options  Settings for the instance
     * 
     */
    public function __construct( $options = null )
    {

    }
}
