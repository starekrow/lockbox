<?php
/**
 * Copyright (C) 2017 David O'Riva. MIT License.
 * Original at: https://github.com/starekrow/lockbox
 */

namespace starekrow\Lockbox;

/**
 * CryptoCore - An interface for various cryptographic functions
 *
 * @package starekrow\Lockbox
 */
interface CryptoCore
{
    function hash( $alg, $data );
    function hmac( $alg, $key, $data );
    function hkdf( $alg, $ikm, $len, $salt = "", $info = "" );
    function encrypt( $alg, $key, $iv, $data );
    function decrypt( $alg, $key, $iv, $data );
    function hashdiff( $h1, $h2 );
    function random( $count );
    function ivlen( $alg );
    function keylen( $alg );
    function hashlen( $alg );
    function algolist();
}
