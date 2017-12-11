<?php
/**
 * Copyright (C) 2017 David O'Riva. MIT License.
 * Original at: https://github.com/starekrow/lockbox
 */

namespace starekrow\Lockbox;
use Exception;

/**
 * CryptoCoreOpenssl - Cryptographic driver using OpenSSL
 *
 * Builds on `CryptoCoreBuiltin` for hashing.
 * 
 * @package starekrow\Lockbox
 */
class CryptoCoreOpenssl
    extends CryptoCoreBuiltin
{
    public function encrypt( $alg, $key, $iv, $data )
    {
        $options = OPENSSL_RAW_DATA;
        return openssl_encrypt($data, $alg, $key, $options, $iv);
    }
    public function decrypt( $alg, $key, $iv, $data )
    {
        $options = OPENSSL_RAW_DATA;
        return openssl_decrypt($data, $alg, $key, $options, $iv);
    }
    public function random( $count )
    {
        return openssl_random_pseudo_bytes( $count );
    }
    public function ivlen( $alg )
    {
        return openssl_cipher_iv_length( $alg );
    }
    public function keylen( $alg )
    {
        throw new Exception( "Unknown algorithm" );
    }
    public function algolist()
    {
        $got = parent::algolist();
        $got[ 'cipher' ] = openssl_get_cipher_methods();
        return $got;
    }
}
