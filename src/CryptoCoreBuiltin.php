<?php
/**
 * Copyright (C) 2017 David O'Riva. MIT License.
 * Original at: https://github.com/starekrow/lockbox
 */

namespace starekrow\Lockbox;

use Exception;

/**
 * CryptoCoreBuiltin - Uses built-in PHP functions where possible
 *
 * This crypto driver implements the core capabilities possible using only
 * built-in functions. It covers mostly hashing and random number generation.
 * For encryption, we'd need to add in some software drivers, and openssl is
 * pervasive enough that maybe that'll never be needed.
 *
 * @package starekrow\Lockbox
 */
class CryptoCoreBuiltin implements CryptoCore
{
    protected $cache = [];

    public function hash($alg, $data)
    {
        return hash($alg, $data, true);
    }
    public function hmac($alg, $key, $data)
    {
        return hash_hmac($alg, $data, $key, true);
    }
    public function hkdf($alg, $ikm, $len, $salt = "", $info = "")
    {
        if (function_exists("hash_hkdf")) {
            return hash_hkdf($alg, $ikm, $len, $info, $salt);
        }
        $prk = hash_hmac($alg, $ikm, $salt, true);
        $okm = "";
        $t = "";
        for ($i = 1; strlen($okm) < $len; $i++) {
            $t = hash_hmac($alg, $t . $info . chr($i), $prk, true);
            $okm .= $t;
        }

        return substr($okm, 0, $len);
    }
    public function encrypt($alg, $key, $iv, $data)
    {
        throw new Exception("No usable encryptor");
    }
    public function decrypt($alg, $key, $iv, $data)
    {
        throw new Exception("No usable decryptor");
    }
    public function hashdiff($h1, $h2)
    {
        if (function_exists("hash_equals")) {
            return !hash_equals($h1, $h2);
        }
        if (strlen($h1) !== strlen($h2)) {
            return false;
        }
        $x = $h1 ^ $h2;
        $ret = 0;
        for ($i = strlen($x) - 1; $i >= 0; $i--) {
            $ret |= ord($x[$i]);
        }

        return !!$ret;
    }
    public function random($count)
    {
        if (function_exists("random_bytes")) {
            return random_bytes($count);
        }
        // TODO: windows: COM stuff, linux: /dev/urandom
        if (function_exists("openssl_random_pseudo_bytes")) {
            return openssl_random_pseudo_bytes($count);
        }

        throw new Exception("No good source of randomness found");
    }
    public function ivlen($alg)
    {
        throw new Exception("Unknown algorithm");
    }
    public function keylen($alg)
    {
        throw new Exception("Unknown algorithm");
    }
    public function hashlen($alg)
    {
        $k = "hashlen-$alg";
        if (empty($this->cache[ $k ])) {
            $tmp = $this->hash($alg, "blahblahblah");
            $this->cache[ $k ] = strlen($tmp);
        }

        return $this->cache[ $k ];
    }
    public function algolist()
    {
        return [
             "hash" => hash_algos()
            ,"cipher" => []
        ];
    }
}
