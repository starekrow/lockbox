<?php

namespace starekrow\Lockbox;

/**
 * Tokens are a compact envelope for encrypted data. They provide the following
 * features:
 * 
 *   - HMAC signatures to prevent tampering
 *   - AES encryption
 *   - URL-safe representation
 *   - simple key creation and management
 *   - easy key rotation or token versioning
 *   - compact form for limited bandwidth connections
 *   - strong form for future-proof security
 *   - expandable format
 * 
 * Use
 * ---
 * 
 * 
 * 
 * 
 * 
 * 
 * 
 * 
 * Format
 * ------
 * 
 * The token format is designed to URL-safe while still limiting the overhead
 * required for format and encoding information. It offers a diverse selection
 * of types that trade off size and complexity against security. The weakest
 * available token is still more than sufficiently secure to defeat any attempt
 * to decode or tamper with it using currently available technology.
 * 
 * Structurally, the token is formed of two strings separated by a period
 * (".") character. The strings are in a URL-safe base-64 encoding, and decode
 * to binary strings. 
 * 
 * The first string is the header, and the first byte in the header is a "flags
 * byte", described below. The remainder of the header is a signature for the
 * payload.
 * 
 * The payload is the second string, and it is encrypted with an algorith that
 * depends on the type of the token. This type is specified within the flags 
 * byte. After decryption, the first byte of the payload is a copy of the flags
 * byte, and the remainder is either a binary string or JSON-encoded data, 
 * depending on another field in the flags byte.
 * 
 * ### Flags Byte
 * 
 * The flags byte contains the following bitfields:
 * 
 *   - bits 0 - 3: key index
 *   - bits 4 - 5: token type
 *     0. Normal
 *     1. Compact
 *     2. Secure
 *     3. there is no 3
 *   - bit 6: data type
 *     0. binary string
 *     1. JSON-encoded data
 *   - bit 7: reserved for header extension
 * 
 * The key index is a 4-bit unsigned integer field available for the 
 * application's use. This could be used, for example, to choose a key from a 
 * set of up to sixteen available keys. This value can be seen and used without
 * decrypting the token.
 * 
 * The token type selected affects the encryption and authentication of the
 * token, and influences its total length. The possible types are:
 * 
 *   - Normal: A normal token uses AES-128 for encryption, SHA-1 for the HMAC
 *     authentication, and KDF1 to generate keys.
 *   - Compact: Uses the same algorithms as the normal token, but only 
 *     includes the first 10 bytes of the HMAC for athentication.
 *   - Secure: Secure tokens encrypt with AES-256 and use HKDF with SHA-512 for
 *     authentication. An additional 256-bit salt is generated and stored
 *     before the signature.
 * 
 * Crypto
 * ------
 * 
 * 
 * 
 * 
 * 
 * 
 * 
 */
class Token
{
    const KEY_INDEX_MASK                =   0x0f;
    const TOKEN_TYPE_MASK               =   0x30;

    const SECURE_TOKEN                  =   0x00;
    const COMPACT_TOKEN                 =   0x10;
    const QUICK_TOKEN                   =   0x20;

    const JSON_PAYLOAD                  =   0x40;

    const AES_BLOCK_SIZE                =   16;
    const AES128_KEY_LENGTH             =   16;
    const AES256_KEY_LENGTH             =   16;
    const SHA1_LENGTH                   =   20;
    const SHA256_LENGTH                 =   32;
    const SHA512_LENGTH                 =   64;


    static function base64url_encode($input) {
        return str_replace('=', '', strtr(base64_encode($input), '+/', '-_'));
    }  
    static function base64url_decode($input) {
        return base64_decode(str_pad(strtr($input, '-_', '+/'), (4 - strlen($input)) & 3));
    }
    static function hashlen($algo)
    {
        switch (strtolower(str_replace('-', '', $algo))) {
            case 'md5':             return 16;
            case 'sha1':            return 20;
            case 'sha256':          return 32;
            case 'sha512':          return 64;
        }
        return strlen(hash($algo,"test",true));
    }
    static function hash($algo, $data)
    {
        return hash($algo, $data, true);
    }
    static function hmac($algo, $data, $key)
    {
        return hash_hmac($algo, $data, $key, true);
    }
    static function random($length)
    {
        return random_bytes($length);
    }
    static function kdf1($algo, $length, $key, $context = "")
    {
        $hashlen = self::hashlen($algo);
        $reps = ceil($length / $hashlen);
        $out = "";
        for ($i = 0; $i < $reps; $i++) {
            $out .= self::hash($algo, $key . pack('N', $i) . $context);
        }
        return substr($out, 0, $length);
    }
    static function hkdf($algo, $sourceKey, $context = "", $salt = "")
    {

    }

    static function pkcs7pad($data, $blocksize)
    {
        $pad = $blocksize - (strlen($data) % $blocksize);
        return $data . str_repeat(chr($pad), $pad);
    }

    static function pkcs7unpad($data, $blocksize)
    {
        $len = strlen($data);
        $pad = ord($data[$len - 1]);
        if ($pad < 1 || $pad > $blocksize || ($len - $pad) % $blocksize != 0) {
            return null;
        }
        return substr($data, 0, $len - $pad);
    }

    static function aes_mcrypt($operation, $data, $key)
    {
        if ($operation == 'encrypt') {
            $payload = self::pkcs7pad($data, self::AES_BLOCK_SIZE);
            $iv = mcrypt_create_iv(self::AES_BLOCK_SIZE, MCRYPT_DEV_URANDOM);
            $crypt = mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $key, $payload, MCRYPT_MODE_CBC, $iv);
            return $iv . $crypt;
        } else if ($operation == 'decrypt') {
            $iv = substr($data, 0, self::AES_BLOCK_SIZE);
            $ctext = substr($data, self::AES_BLOCK_SIZE);
            $ptext = mcrypt_decrypt(MCRYPT_RIJNDAEL_128, $key, $ctext, MCRYPT_MODE_CBC, $iv);
            return self::pkcs7unpad($ptext, self::AES_BLOCK_SIZE);
        }
        return null;
    }

    static function aes_openssl($operation, $data, $key)
    {
        if ($operation == 'encrypt') {
            $iv = openssl_random_pseudo_bytes(self::AES_BLOCK_SIZE);
            $bits = strlen($key->encrypt) << 3;
            $crypt = openssl_encrypt($data , "AES-$bits-CBC", $key->encrypt, OPENSSL_RAW_DATA, $iv);
            return $iv . $crypt;
        } else if ($operation == 'decrypt') {
            $iv = substr($data, 0, self::AES_BLOCK_SIZE);
            $bits = strlen($key->encrypt) << 3;
            $ctext = substr($data, self::AES_BLOCK_SIZE);
            $ptext = openssl_decrypt($ctext, "AES-$bits-CBC", $key->encrypt, OPENSSL_RAW_DATA, $iv);
            return $ptext;
        }
        return null;
    }

    static function aes($operation, $data, $key)
    {
        if (function_exists('openssl_encrypt')) {
            return self::aes_openssl($operation, $data, $key);
        } else if (function_exists('mcrypt_encrypt')) {
            return self::aes_openssl($operation, $data, $key);
        }
        return null;
    }
    static function parse($data)
    {
        if (!$data || !is_string($data)) {
            return null;
        }
        $parts = explode(".", $data);
        if (count($parts) != 2 || strlen($parts[0]) < 1 
                               || strlen($parts[1]) < 1) {
            return null;
        }
        $header = self::base64url_decode($parts[0]);
        $payload = self::base64url_decode($parts[1]);
        if  ($header === null || $payload === null) {
            return null;
        }
        return (object) [
            'flags' => ord($header[0]),
            'sig' => substr($header, 1),
            'payload' => $payload
        ];
    }

    static function flags($token)
    {
        if (!is_string($token) || strlen($token) < 2) {
            return null;
        }
        $v = self::base64url_decode(substr($token, 0, 4));
        if (!is_array($v)) {
            return null;
        }
        return ord($v[0]);
    }

    static function setupKey($key, $flags, $salt = null)
    {
        if (is_array($key) && isset($key[$flags & self::KEY_INDEX_MASK])) {
            $key = $key[$flags & self::KEY_INDEX_MASK];
        }
        if (is_array($key)) {
            $key = (object)$key;
        }
        if (is_object($key) && isset($key->verify) && isset($key->encrypt)) {
            if (($flags & self::TOKEN_TYPE_MASK) == self::SECURE_TOKEN && !isset($key->salt)) {
                return null;
            }
            return $key;
        }
        if (!is_string($key)) {
            return null;
        }
        switch ($flags & self::TOKEN_TYPE_MASK) {
            case self::QUICK_TOKEN:
                return (object)[
                    'verify' => self::kdf1("sha256", self::SHA256_LENNGTH, $key, "verify"),
                    'encrypt' => self::kdf1("sha256", self::AES128_KEY_LENGTH, $key, "encrypt")
                ];
            case self::COMPACT_TOKEN:
                return (object)[
                    'verify' => self::kdf1("sha1", self::SHA1_LENGTH, $key, "verify"),
                    'encrypt' => self::kdf1("sha1", self::AES128_KEY_LENGTH, $key, "encrypt")
                ];
            case self::SECURE_TOKEN:
                if ($salt === null) {
                    $salt = random_bytes(self::SHA512_LENGTH);
                }
                return (object)[
                    'verify' => self::hkdf("sha512", self::SHA512_LENGTH, $key, "verify", $salt),
                    'encrypt' => self::hkdf("sha256", self::AES256_KEY_LENGTH, $key, "encrypt"),
                    'salt' => $salt
                ];
        }
        return null;
    }

    static function sign($data, $key, $flags)
    {
        switch ($flags & self::TOKEN_TYPE_MASK) {
            case self::QUICK_TOKEN:
                return self::hmac('sha256', $data, $key->verify);
            case self::COMPACT_TOKEN:
                return substr(self::hmac('sha1', $data, $key->verify), 0, 10);
            case self::SECURE_TOKEN:
                return $key->salt . self::hkdf('sha512', $data, 'encrypt', $key->salt);
        }
        return null;
    }

    static function encode($data, $key, $flags = 0)
    {
        $key = self::setupKey($key, $flags);
        if (!$key || !is_int($flags) || $flags > 127 || $flags < 0) {
            return "";
        }
        if (!is_string($data)) {
            $data = json_encode($data);
            if ($data === null) {
                return "";
            }
            $flags |= self::JSON_PAYLOAD;
        }
        $data .= chr($flags);
        $header = chr($flags) . self::sign($data, $key, $flags);
        $payload = self::aes('encrypt', $data, $key);
        return self::base64url_encode($header) . '.' . self::base64url_encode($payload);
    }

    static function decode($token, $key)
    {
        $t = self::parse($token);
        $salt = null;
        if (($t->flags & self::TOKEN_TYPE_MASK) == self::SECURE_TOKEN) {
            $salt = substr($t->key, 0, SHA512_LENGTH);
        }
        $key = self::setupKey($key, $t->flags, $salt);
        $ptext = self::aes('decrypt', $t->payload, $key);
        $plen = strlen($ptext);
        if ($ptext === null || ord($ptext[$plen - 1]) !== $t->flags) {
            return null;
        }
        return substr($ptext, 0, $plen - 1);
    }

    function __construct($flags, $key = null)
    {

    }
}

$data = '{"did":1234567890}';
$key = "hi";
$tok = Token::encode($data, $key, Token::COMPACT_TOKEN);
echo strlen($tok) . " bytes: $tok" . PHP_EOL;

$t2 = Token::decode($tok, $key);
echo $t2 . PHP_EOL;
