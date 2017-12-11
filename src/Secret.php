<?php
/**
 * Copyright (C) 2017 David O'Riva. MIT License.
 * Original at: https://github.com/starekrow/lockbox
 */

namespace starekrow\Lockbox;

/**
 * Secret - Management for secret values with multiple lockboxes
 *
 * When a secret is created, a new internal key is generated to encrypt it. You
 * never work with this key directly. Instead, you add your own keys to the
 * secret. Each key you add will create a corresponding lockbox that contains the
 * internal key. This can be used to support a number of traditionally difficult
 * features, like non-atomic key rotation and separation of key management from
 * secret value access.
 *
 * Storage of secret data is outside the scope of this class. Use the provided
 * Import() and Export() functions to work with a printable representation of
 * the encrypted secret data and lockboxes.
 *
 * TODO: extend serializable
 *
 * @package starekrow\Lockbox
 */
class Secret
{
    /**
     * whether the secret is currently locked. It's read only.
     * Don't make me stick it behind a getter.
     *
     * @var bool
     */
    public $locked;
    protected $value;
    protected $decrypted;
    protected $locks;
    protected $key;
    protected $ciphertext;


    /**
     * Unlock - Unlocks the secret
     *
     * Supply a CryptoKey (in exported or instantiated form).
     *
     * If no key is given, returns true if the secret is already unlocked.
     * Otherwise, returns true if the given key fits a lockbox.
     *
     * The secret value is not actually decrypted here, but on the first call to
     * Read(). This supports the case where you are adding, removing or rotating a
     * key and there is no need to risk exposing the fully decrypted secret value
     * in RAM.
     *
     * @param $key
     *
     * @return bool
     */
    public function unlock($key = null)
    {
        if (!$key) {
            return !$this->locked;
        }
        if (is_string($key)) {
            $key = CryptoKey::import($key);
            if (!$key) {
                return false;
            }
        }
        if (empty($this->locks[$key->id])) {
            return false;
        }
        $got = $key->unlock($this->locks[$key->id]);
        $ikey = CryptoKey::import($got);

        if (!$ikey) {
            return false;
        }
        $this->key = $ikey;
        $this->locked = false;
        return true;
    }

    /**
     * Lock - Lock the secret
     *
     * Erases the stored data key and decrypted value.
     *
     * @return bool
     */
    public function lock()
    {
        if ($this->locked) {
            return true;
        }
        $this->key = null;
        $this->value = null;
        $this->decrypted = false;
        $this->locked = true;
        return true;
    }

    /**
     * Update
     *
     * Update the secret value. The secret must already be unlocked.
     *
     * Returns `true` if the value was updated, otherwise `false`.
     *
     * @param $value
     *
     * @return bool
     */
    public function update($value)
    {
        if ($this->locked) {
            return false;
        }
        if (is_object($value)) {
            $value = (object)((array)$value);
        }
        $this->value = $value;
        $this->decrypted = true;
        if (is_string($this->value)) {
            $plaintext = "s" . $value;
        } else {
            $plaintext = "p" . serialize($value);
        }
        $this->ciphertext = $this->key->lock($plaintext);
        return true;
    }

    /**
     * Read
     *
     * Gets the secret's value (or `false` if it cannot be decrypted).
     *
     * @return bool|mixed|string
     */
    public function read()
    {
        if ($this->decrypted) {
            return $this->value;
        }
        if ($this->locked) {
            return false;
        }
        $value = $this->key->unlock($this->ciphertext);
        if ($value === false) {
            return false;
        }
        if ($value[0] == "s") {
            $this->value = substr($value, 1);
        } else {
            if ($value[0] == "p") {
                $this->value = unserialize(substr($value, 1));
            }
        }
        $this->decrypted = true;
        return $this->value;
    }

    /**
     * AddLockbox
     *
     * Adds a lockbox to the secret. The secret must already be unlocked for this
     * to succeed.
     *
     * @param $key
     *
     * @return bool
     */
    public function addLockbox($key)
    {
        if (is_string($key)) {
            $key = CryptoKey::import($key);
        }
        $this->locks[$key->id] = $key->lock($this->key->export());
        return true;
    }


    /**
     * RemoveLockbox
     *
     * Removes a lock from the secret. Works whether the secret is unlocked or
     * not.
     *
     * Returns `true` if the lock was found and removed, otherwise `false`.
     *
     * @param $id
     *
     * @return bool
     */
    public function removeLockbox($id)
    {
        if (!empty($this->locks[$id])) {
            unset($this->locks[$id]);
            return true;
        }

        return false;
    }

    /**
     * ListLockboxes
     *
     * Returns an array containing a list of all locks present on the secret.
     *
     * @return array
     */
    public function listLockboxes()
    {
        return array_keys($this->locks);
    }

    /**
     * HasLockbox
     *
     * Returns `true` if the given lock is present on the secret, otherwise
     * `false`.
     *
     * @param $id
     *
     * @return bool
     */
    public function hasLockbox($id)
    {
        return !empty($this->locks[$id]);
    }

    /**
     * Export
     *
     * Returns a string containing a "safe" representation of the secret and any
     * attached lockboxes.
     *
     * @return string
     */
    public function export()
    {
        return json_encode([
            "locks" => $this->locks
            , "data" => $this->ciphertext
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    }

    /**
     * Import (static)
     *
     * Returns a secret built from the given (previously exported) string.
     * Returns `false` if the data cannot be imported.
     *
     * @param $data
     *
     * @return Secret
     */
    public static function import($data)
    {
        $data = json_decode($data);
        return new Secret(null, $_import = $data);
    }

    /**
     * Secret constructor.
     *
     * Builds a new secret from a value.
     *
     * @param      $value
     * @param null $_import
     */
    public function __construct($value, $_import = null)
    {
        if ($_import) {
            $this->locks = (array)$_import->locks;
            $this->ciphertext = $_import->data;
            $this->locked = true;
            return;
        }
        $this->locked = false;
        $this->locks = [];
        $this->key = new CryptoKey();
        $this->update($value);
    }
}
