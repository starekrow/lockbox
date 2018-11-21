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
        for ($i = 0; $i < reps; $i++) {
            $out .= self::hash($key . pack('N', $i) . $context);
        }
        return substr($out, 0, $length);
    }
    static function hkdf($algo, $sourceKey, $context = "", $salt = "")
    {

    }

    static function aes($operation, $data, $key)
    {

    }

    static function encode($data, $key, $flags = 0)
    {

    }

    static function decode($data, $key)
    {

    }

    static function parse($data)
    {
        if (!$data || !is_string($data)) {
            return null;
        }
        $parts = explode(".", $data);

    }

    function sign($data)
    {

    }

    function generate($data)
    {

    }

    function __construct($flags, $key)
    {

    }
}
