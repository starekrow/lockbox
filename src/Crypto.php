<?php
/**
 * Copyright (C) 2017 David O'Riva. MIT License.
 * Original at: https://github.com/starekrow/lockbox
 */

namespace starekrow\Lockbox;

/**
 * Crypto - Basic encryption support
 *
 * Provides a static interface to various cryptographic functions. Uses a 
 * driver-based model to simplify adaptation to different platforms.
 * 
 * See also `CryptoCore` et al.
 * 
 * @package starekrow\Lockbox
 */
class Crypto 
{
    protected static $impl;

    public static function init( $provider = null )
    {
        if (!$provider) {
            // TODO: sodium support
            //if (is_function( "sodium_crypto_secretbox" )) {
            //    $provider = "sodium";
            //} else 
            if (function_exists( "openssl_encrypt" )) {
                $provider = "openssl";
            } else {
                $provider = "builtin";
            }
        }
        $cls = "starekrow\\Lockbox\\CryptoCore" . ucwords( $provider );
        try {
            self::$impl = new $cls;
        } catch (\Exception $e) {
            self::$impl = new CryptoCoreFailed();
            return false;
        }
    }

    public static function hash( $alg, $data )
    {
        return self::$impl->hash( $alg, $data );
    }
    public static function hmac( $alg, $key, $data )
    {
        return self::$impl->hmac( $alg, $key, $data );
    }
    public static function hkdf( $alg, $ikm, $len, $salt = "", $info = "" )
    {
        return self::$impl->hkdf( $alg, $ikm, $len, $salt, $info );
    }
    public static function encrypt( $alg, $key, $iv, $data )
    {
        return self::$impl->encrypt( $alg, $key, $iv, $data );
    }
    public static function decrypt( $alg, $key, $iv, $data )
    {
        return self::$impl->decrypt( $alg, $key, $iv, $data );
    }
    public static function hashcmp( $h1, $h2 )
    {
        return self::$impl->hashcmp( $h1, $h2 );
    }
    public static function random( $count )
    {
        return self::$impl->random( $count );
    }
    public static function ivlen( $alg )
    {
        return self::$impl->ivlen( $alg );
    }
    public static function keylen( $alg )
    {
        return self::$impl->keylen( $alg );
    }
    public static function algolist( $alg )
    {
        return self::$impl->algolist( $alg );
    }
}

Crypto::init( "Loader" );
