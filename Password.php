<?php

namespace Delight\Auth;

final class PasswordHash {

    private const HASH_ALGO = \PASSWORD_DEFAULT;
    private const PEPPER = 'bec95beffb3afd078df7cbfd4c4617ba214ac4641a157c1ca64106e7544c9fb4cef6e99b0a8f0b63e96328c09943ce96b9b8899ff54fa7ea57b622675442dbbf';
    private const PREFIX = '$pa01';
    private const PREFIX_LEN = 5;

    /**
     * Creates a computationally expensive hash from a password
     *
     * @param string $password
     * @return string|bool
     */
    public static function from(string $password) {
        $useBcrypt = self::HASH_ALGO === \PASSWORD_BCRYPT || self::HASH_ALGO === null;

        if ($useBcrypt) {
            $password = self::prehash($password);
            $prefix = self::PREFIX;
        }
        else {
            $prefix = '';
        }

        return $prefix . \password_hash($password, self::HASH_ALGO);
    }

    /**
     * Verifies whether a password matches a computationally expensive hash
     *
     * @param string $password
     * @param string $expectedHash
     * @return bool
     */
    public static function verify(string $password, string $expectedHash): bool {
        if (self::hasPrefix($expectedHash)) {
            $password = self::prehash($password);
            $expectedHash = self::stripPrefix($expectedHash);
        }

        return \password_verify($password, $expectedHash);
    }

    /**
     * Checks whether a computationally expensive hash needs to be updated
     *
     * @param string $existingHash
     * @return bool
     */
    public static function needsRehash(string $existingHash): bool {
        if (self::hasPrefix($existingHash)) {
            $existingHash = self::stripPrefix($existingHash);
        }

        return \password_needs_rehash($existingHash, self::HASH_ALGO);
    }

    /**
     * Applies HMAC-SHA512 prehash with pepper and Base64 encoding
     *
     * @param string $password
     * @return string
     */
    private static function prehash(string $password): string {
        $pepper = \hex2bin(self::PEPPER);

        $hmac = \hash_hmac('sha512', $password, $pepper, true);

        if (!$hmac) {
            throw new AuthError('Could not generate HMAC');
        }

        return \base64_encode($hmac);
    }

    /**
     * Checks if the hash contains the custom prefix
     */
    private static function hasPrefix(string $hash): bool {
        return \strncmp($hash, self::PREFIX, self::PREFIX_LEN) === 0;
    }

    /**
     * Removes the custom prefix from the hash
     */
    private static function stripPrefix(string $hash): string {
        return \substr($hash, self::PREFIX_LEN);
    }
}
