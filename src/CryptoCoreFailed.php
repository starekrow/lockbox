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
class CryptoCoreFailed implements CryptoCore
{
    public function hash($alg, $data)
    {
        throw new Exception("No usable crypto core");
    }
    public function hmac($alg, $key, $data)
    {
        throw new Exception("No usable crypto core");
    }
    public function hkdf($alg, $ikm, $len, $salt = "", $info = "")
    {
        throw new Exception("No usable crypto core");
    }
    public function encrypt($alg, $key, $iv, $data)
    {
        throw new Exception("No usable crypto core");
    }
    public function decrypt($alg, $key, $iv, $data)
    {
        throw new Exception("No usable crypto core");
    }
    public function hashdiff($h1, $h2)
    {
        throw new Exception("No usable crypto core");
    }
    public function random($count)
    {
        throw new Exception("No usable crypto core");
    }
    public function ivlen($alg)
    {
        throw new Exception("No usable crypto core");
    }
    public function keylen($alg)
    {
        throw new Exception("No usable crypto core");
    }
    public function hashlen($alg)
    {
        throw new Exception("No usable crypto core");
    }
    public function algolist()
    {
        throw new Exception("No usable crypto core");
    }
}
