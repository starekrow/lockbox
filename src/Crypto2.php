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

class Crypto2
{
    public function base64url_encode($bytes)
    {

    }

    public function base64url_decode($bytes)
    {

    }

    public function hash($also, $data)
    {
        return hash($algo, $data, true);
    }

    public function hmac($algo, $data, $key)
    {
        return hash_hmac($algo, $data, $key, true);
    }

    public function hkdf($algo, $length, $data, $key, $salt = "", $info = "")
    {
        $hlen = $this->hash_length($algo);
    }

    public function kdf1($algo, $length, $data, $info = "")
    {
        $reps = ceil($length / $this->hash_length($algo));
        $out = "";
        for ($i = 0; $i < $reps; ++$i) {
            $out .= $this->hash($algo, $key . pack("N", $i) . $info);
        }
        return substr($out, 0, $length);
    }

    
}