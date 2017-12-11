<?php
/**
 * Copyright (C) 2017 David O'Riva. MIT License.
 * Original at: https://github.com/starekrow/lockbox
 */

namespace starekrow\Lockbox;
use Exception;

/**
 * CryptoCoreLoader - A driver-loading driver
 *
 * This is the default crypto driver. It tries to auto-select a working core 
 * and re-issue the function call.
 *
 * @package starekrow\Lockbox
 */
class CryptoCoreLoader 
    implements CryptoCore
{
    public function hash( $alg, $data )
    {
        Crypto::init();
        return Crypto::hash( $alg, $data );
    }
    public function hmac( $alg, $key, $data )
    {
        Crypto::init();
        return Crypto::hmac( $alg, $key, $data );
    }
    public function hkdf( $alg, $ikm, $len, $salt = "", $info = "" )
    {
        Crypto::init();
        return Crypto::hkdf( $alg, $ikm, $len, $salt, $info );
    }
    public function encrypt( $alg, $key, $iv, $data )
    {
        Crypto::init();
        return Crypto::encrypt( $alg, $key, $iv, $data );
    }
    public function decrypt( $alg, $key, $iv, $data )
    {
        Crypto::init();
        return Crypto::decrypt( $alg, $key, $iv, $data );
    }
    public function hashcmp( $h1, $h2 )
    {
        Crypto::init();
        return Crypto::hashcmp( $h1, $h2 );
    }
    public function random( $count )
    {
        Crypto::init();
        return Crypto::random( $count );
    }
    public function ivlen( $alg )
    {
        Crypto::init();
        return Crypto::ivlen( $alg );
    }
    public function keylen( $alg )
    {
        Crypto::init();
        return Crypto::keylen( $alg );
    }
    public function algolist()
    {
        Crypto::init();
        return Crypto::algolist();
    }
}
