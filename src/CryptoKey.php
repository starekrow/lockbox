<?php
/**
 * Copyright (C) 2017 David O'Riva. MIT License.
 * Original at: https://github.com/starekrow/lockbox
 */

namespace starekrow\Lockbox;

/**
 * CryptoKey - AES Encyption
 *
 * @package starekrow\Lockbox
 */
class CryptoKey
{
    /**
     * a string identifying this key. Freely modifiable, but must
     * only use chars in [-+_=/.a-zA-Z0-9]*
     * @var string
     */
    public $id;
    /**
     * cipher to use. Modify at your own risk
     *
     * @var null|string
     */
    public $cipher = "AES-128-CBC";
    /**
     * binary key data. Not normally accessible.*
     * @var string
     */
    protected $data;

    /**
     * RandomGUID (static) - Generate a random GUID
     *
     * @return string
     */
    public static function randomGuid()
    {
        $data = Crypto::random(16);
        $data[6] = chr(ord($data[6]) & 0x0f | 0x40); // set version to 0100
        $data[8] = chr(ord($data[8]) & 0x3f | 0x80); // set bits 6-7 to 10
        return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4));
    }

    /**
     * Lock - Encrypt a message with this key
     *
     * Returns printable ciphertext for the binary message, or `false` if the key
     * is invalid or encryption failed.
     *
     * @param $message
     *
     * @return bool|string
     */
    public function lock($message)
    {
        if (!$this->data) {
            return false;
        }
        $ivlen = Crypto::ivlen( $this->cipher );
        $iv = Crypto::random( $ivlen );
        $ciphertext_raw = Crypto::encrypt($this->cipher, $this->data, $iv, 
            $message);
        $hmac = Crypto::hmac('sha256', $this->data, $ciphertext_raw );
        $ciphertext = base64_encode($iv . $hmac . $ciphertext_raw);
        return $ciphertext;
    }

    /**
     *
     * Unlock - Decrypt ciphertext with this key
     *
     * Returns the decrypted binary message, or `false` if the key didn't work.
     *
     * @param $ciphertext
     *
     * @return bool|string
     */
    public function unlock($ciphertext)
    {
        $sha2len = 32;
        $ivlen = Crypto::ivlen($this->cipher);
        $c = base64_decode($ciphertext);
        $iv = substr($c, 0, $ivlen);
        $hmac = substr($c, $ivlen, $sha2len);
        $ciphertext_raw = substr($c, $ivlen + $sha2len);
        $plaintext = Crypto::decrypt( $this->cipher, $this->data, 
            $iv, $ciphertext_raw );
        $calcmac = Crypto::hmac('sha256', $this->data, $ciphertext_raw);
        $diff = Crypto::hashdiff( $hmac, $calcmac );
        return $diff ? false : $plaintext;
    }

    /**
     * Shred - Erase this key from memory
     *
     * Placeholder for eventual functionality. For now, this just releases the
     * string containing the key to the garbage collector.
     *
     * It is an error to try to use this key after it is shredded.
     */
    public function shred()
    {
        $this->data = null;
        $this->id = null;
        $this->cipher = null;
    }

    /**
     * Export
     *
     * Returns a printable string containing a representation of the key, with the
     * ID and cipher in use. This is probably sensitive information.
     *
     * @return string
     */
    public function export()
    {
        $id = $this->id;
        $cp = base64_encode($this->cipher);
        $kd = base64_encode($this->data);
        return "k0|$id|$cp|$kd";
    }

    /**
     * Import (static)
     *
     * Returns a CryptoKey built from the given (previously exported) string.
     * Returns `false` if the key cannot be imported.
     *
     * @param $data
     *
     * @return bool|CryptoKey
     */
    public static function import($data)
    {
        if (!is_string($data)) {
            return false;
        }
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

    /**
     * CryptoKey constructor.
     *
     * Sets up the key.
     * `data` - A binary string containing key data. If `null`, a new
     * 256-bit random key is generated.
     * `id` - A string identifying this key. May only contain characters
     * from the set:
     * a-z A-Z 0-9 / = - + _ .
     * May be read through the `id` property of the object.
     * If `null`, a new 128-bit random id (as a GUID) is generated.
     *
     * @param null $data
     * @param null $id
     * @param null $cipher
     */
    public function __construct($data = null, $id = null, $cipher = null)
    {
        $this->data = $data;
        if (!$data) {
            $this->data = Crypto::random(32);
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
