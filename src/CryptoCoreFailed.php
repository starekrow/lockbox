<?php
/**
 * Copyright (C) 2017 David O'Riva. MIT License.
 * Original at: https://github.com/starekrow/lockbox
 */

namespace starekrow\Lockbox;
use Exception;

/**
 * CryptoCoreFailed - An unusable cryptographic driver
 *
 * This will be used in cases where a required core has failed to initialize.
 * 
 * @package starekrow\Lockbox
 */
class CryptoCoreFailed 
    implements CryptoCore
{
    protected function hash( $alg, $data )
    {
        throw new Exception( "No usable crypto core" );
    }
    protected function hmac( $alg, $key, $data )
    {
        throw new Exception( "No usable crypto core" );
    }
    protected function hkdf( $alg, $ikm, $len, $salt = "", $info = "" )
    {
        throw new Exception( "No usable crypto core" );
    }
    protected function encrypt( $alg, $key, $iv, $data )
    {
        throw new Exception( "No usable crypto core" );
    }
    protected function decrypt( $alg, $key, $iv, $data )
    {
        throw new Exception( "No usable crypto core" );
    }
    protected function hashcmp( $h1, $h2 )
    {
        throw new Exception( "No usable crypto core" );
    }
    protected function random( $count )
    {
        throw new Exception( "No usable crypto core" );
    }
    protected function ivlen( $alg )
    {
        throw new Exception( "No usable crypto core" );
    }
    protected function keylen( $alg )
    {
        throw new Exception( "No usable crypto core" );
    }
    protected function algolist()
    {
        throw new Exception( "No usable crypto core" );
    }
}
