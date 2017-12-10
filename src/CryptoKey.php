<?php /* Copyright (C) 2017 David O'Riva. MIT License.
       * Original at: https://github.com/starekrow/lockbox
       ********************************************************/

namespace starekrow\Lockbox;

/*
================================================================================
CryptoKey - AES Encyption
================================================================================
*/
class CryptoKey
{
    // `id` - a string identifying this key. Freely modifiable, but must
    // only use chars in [-+_=/.a-zA-Z0-9]
    public $id;
    // `cipher` - cipher to use. Modify at your own risk
    public $cipher = "AES-128-CBC";
    // `data` - binary key data. Not normally accessible.
    protected $data;

    /*
    =====================
    RandomGUID (static) - Generate a random GUID
    =====================
    */
    public static function randomGuid()
    {
        $data = openssl_random_pseudo_bytes(16);
        $data[6] = chr(ord($data[6]) & 0x0f | 0x40); // set version to 0100
        $data[8] = chr(ord($data[8]) & 0x3f | 0x80); // set bits 6-7 to 10
        return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4));
    }

    /*
    =====================
    HashEquals (static) - Compare hashes in contant time
    =====================
    */
    public static function hashEquals($h1, $h2)
    {
        if (is_function("hash_equals")) {
            return hash_equals($h1, $h2);
        }
        if (strlen($h1) != strlen($h2)) {
            return false;
        } else {
            $res = $h1 ^ $h2;
            $ret = 0;
            for ($i = strlen($res) - 1; $i >= 0; $i--) {
                $ret |= ord($res[$i]);
            }
            return !$ret;
        }
    }

    /*
    =====================
    HashHKDF (static) - Compute HKDF

    Only a few hash functions are required for our purposes.
    =====================
    */
    public static function hashHkdf($alg, $ikm,
                                    $length = null, $info = "", $salt = "")
    {
        if (is_function("hash_hkdf")) {
            return hash_hkdf($alg, $ikm, $length, $info, $salt);
        }
        $prk = hash_hmac($alg, $ikm, $salt, true);
        $okm = "";
        $t = "";
        for ($i = 1; strlen($okm) < $length; $i++) {
            $t = hash_hmac($alg, $t . $info . chr($i), $prk, true);
            $okm .= $t;
        }
        return substr($okm, 0, $length);
    }

    /*
    =====================
    Lock - Encrypt a message with this key

    Returns printable ciphertext for the binary message, or `false` if the key
    is invalid or encryption failed.
    =====================
    */
    public function lock($message)
    {
        if (!$this->data) {
            return false;
        }
        $options = OPENSSL_RAW_DATA;
        $ivlen = openssl_cipher_iv_length($this->cipher);
        $iv = openssl_random_pseudo_bytes($ivlen);
        $ciphertext_raw = openssl_encrypt($message, $this->cipher, $this->data,
            $options, $iv);
        $hmac = hash_hmac('sha256', $ciphertext_raw, $this->data,
            $as_binary = true);
        $ciphertext = base64_encode($iv . $hmac . $ciphertext_raw);
        return $ciphertext;
    }

    /*
    =====================
    Unlock - Decrypt ciphertext with this key

    Returns the decrypted binary message, or `false` if the key didn't work.
    =====================
    */
    public function unlock($ciphertext)
    {
        $sha2len = 32;
        $options = OPENSSL_RAW_DATA;
        $ivlen = openssl_cipher_iv_length($this->cipher);
        $c = base64_decode($ciphertext);
        $iv = substr($c, 0, $ivlen);
        $hmac = substr($c, $ivlen, $sha2len);
        $ciphertext_raw = substr($c, $ivlen + $sha2len);
        $plaintext = openssl_decrypt($ciphertext_raw,
            $this->cipher, $this->data, $options, $iv);
        $calcmac = hash_hmac('sha256', $ciphertext_raw, $this->data,
            $as_binary = true);
        $res = 0;

        for ($i = 0; $i < strlen($hmac); ++$i) {
            $res |= (($hmac[$i] != $calcmac[$i]) ? 1 : 0);
        }
        return $res ? false : $plaintext;
    }

    /*
    =====================
    Shred - Erase this key from memory

    Placeholder for eventual functionality. For now, this just releases the
    string containing the key to the garbage collector.

    It is an error to try to use this key after it is shredded.
    =====================
    */
    public function shred()
    {
        $this->data = null;
        $this->id = null;
        $this->cipher = null;
    }

    /*
    =====================
    Export

    Returns a printable string containing a representation of the key, with the
    ID and cipher in use. This is probably sensitive information.
    =====================
    */
    public function export()
    {
        $id = $this->id;
        $cp = base64_encode($this->cipher);
        $kd = base64_encode($this->data);
        return "k0|$id|$cp|$kd";
    }

    /*
    =====================
    Import (static)

    Returns a CryptoKey built from the given (previously exported) string.
    Returns `false` if the key cannot be imported.
    =====================
    */
    public static function import($data)
    {
        if (!is_string($data)) return false;
        $kp = explode("|", $data);
        if (count($kp) != 4 || $kp[0] != "k0") {
            return false;
        }
        $dat = base64_decode($kp[3]);
        $id = $kp[1];
        if (!$dat) {
            return false;
        }
        return new CryptoKey($dat, $id, base64_decode($kp[2]));
    }

    /*
    =====================
    __construct

    Sets up the key.
      * `data` - A binary string containing key data. If `null`, a new
        256-bit random key is generated.
      * `id` - A string identifying this key. May only contain characters
        from the set:
            a-z A-Z 0-9 / = - + _ .
          May be read through the `id` property of the object.
          If `null`, a new 128-bit random id (as a GUID) is generated.
    =====================
    */
    public function __construct($data = null, $id = null, $cipher = null)
    {
        $this->data = $data;
        if (!$data) {
            $this->data = openssl_random_pseudo_bytes(32);
        }
        if ($id !== null) {
            $this->id = $id;
        } else {
            $this->id = self::randomGuid();
        }
        if ($cipher) {
            $this->cipher = $cipher;
        }
    }
}

