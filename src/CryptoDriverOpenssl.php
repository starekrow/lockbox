<?php

namespace starekrow\Lockbox;

interface CrytoDriver
{
    public function random($bytes);
    public function hash($algo, $data);
    public function hmac($algo, $data, $key);
    public function hkdf($algo, $data, $salt = "", $info = "");
    public function kdf1($algo, $data, $info = "");
    public function aesEncrypt($data, $key);
    public function aesDecrypt($data, $key);
};
