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
    public function hash($alg, $data);
    public function hmac($alg, $key, $data);
    public function hkdf($alg, $ikm, $len, $salt = "", $info = "");
    public function encrypt($alg, $key, $iv, $data);
    public function decrypt($alg, $key, $iv, $data);
    public function hashdiff($h1, $h2);
    public function random($count);
    public function ivlen($alg);
    public function keylen($alg);
    public function hashlen($alg);
    public function algolist();
}
