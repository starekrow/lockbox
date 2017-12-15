<?php
/**
 * Copyright (C) 2017 David O'Riva. MIT License.
 * Original at: https://github.com/starekrow/lockbox
 */

namespace starekrow\Lockbox;

use Exception;

/**
 * CryptoKey - AES Encyption
 *
 * @package starekrow\Lockbox
 */
class CryptoKey
{
    /**
     * salt length
     */
    const SALT_LENGTH = 32;

    /**
     * Current key version
     */
    const CURRENT_KEY_VERSION = 'k1';

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
     * @var string hmac algorithm to use.
     */
    public $mac = 'sha256';

    /**
     * @var string key version
     */
    public $version;

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
     * @throws Exception when version doesn't match one of the defined versions
     */
    public function lock($message)
    {
        if (!$this->data) {
            return false;
        }

        $ivlen = Crypto::ivlen( $this->cipher );
        $iv = Crypto::random( $ivlen );
        $salt = Crypto::random(self::SALT_LENGTH);

        list($encryptionKey, $hmacKey) = $this->getKeys($salt);

        $ciphertext_raw = Crypto::encrypt($this->cipher, $encryptionKey, $iv, $message);

        $hmac = Crypto::hmac($this->mac, $hmacKey, $ciphertext_raw );
        $ciphertext = base64_encode($iv . $hmac . $salt . $ciphertext_raw);

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
     * @throws Exception when the version doesn't match one of the defined versions
     */
    public function unlock($ciphertext)
    {
        $maclen = Crypto::hashlen($this->mac);
        $ivlen = Crypto::ivlen($this->cipher);
        $saltlen = $this->getNumericVersion() > 0 ? self::SALT_LENGTH : 0;

        $c = base64_decode($ciphertext);

        $iv = substr($c, 0, $ivlen);
        $hmac = substr($c, $ivlen, $maclen);
        $salt = $saltlen > 0 ? substr($c, $ivlen + $maclen, $saltlen) : '';
        $ciphertext_raw = substr($c, $ivlen + $maclen + $saltlen);

        list($encryptionKey, $hmacKey) = $this->getKeys($salt);

        $plaintext = Crypto::decrypt( $this->cipher, $encryptionKey, $iv, $ciphertext_raw );
        $calcmac = Crypto::hmac($this->mac, $hmacKey, $ciphertext_raw);
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
        $this->mac = null;
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
        $mac = base64_encode($this->mac);
        return "k1|$id|$cp|$kd|$mac";
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
        $paramCount = count($kp);

        if ($paramCount === 5 && $kp[0] === 'k1') {
            $mac = base64_decode($kp[4]);
            if (!$mac) {
                return false;
            }
        } elseif ($paramCount === 4 && $kp[0] === 'k0') {
            $mac = null;
        } else {
            return false;
        }

        $dat = base64_decode($kp[3]);
        $id = $kp[1];

        if (!$dat) {
            return false;
        }

        return new CryptoKey($dat, $id, base64_decode($kp[2]), $mac, $kp[0]);
    }

    /**
     * gets the encryption key and hmac key
     * @param string $salt
     * @return array [encryption key, hmac key]
     * @throws Exception when the version doesn't match one of the defined versions
     */
    public function getKeys($salt = '')
    {
        switch ($this->version) {
            case 'k0':
                return [$this->data, $this->data];
            case 'k1':
                $keylen = Crypto::keylen($this->cipher);
                $maclen = Crypto::hashlen($this->mac);

                $hmacKey = Crypto::hkdf('sha256', $this->data, $maclen, $salt, 'hmac');
                $encryptionKey = Crypto::hkdf('sha256', $this->data, $keylen, $salt, 'encryption');

                return [$encryptionKey, $hmacKey];
            default:
                throw new Exception('Invalid key version');
        }
    }

    /**
     * gets the numerical version
     * @return int
     */
    public function getNumericVersion()
    {
        return (int) ltrim($this->version, 'k');
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
     * @param string $mac Algorithm to use for hmac (default sha256)
     * @param string $version key version
     */
    public function __construct($data = null, $id = null, $cipher = null, $mac = null, $version = self::CURRENT_KEY_VERSION)
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

        if ($mac) {
            $this->mac = $mac;
        }

        $this->version = $version;
    }
}
