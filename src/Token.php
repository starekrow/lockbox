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
 * 
 * 
 * 
 */
class Token
{
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
