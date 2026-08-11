<?php

namespace Delight\Auth;

final class PasswordHash {

    /** @var int|string Algoritmo usado pelo password_hash */
    private const HASH_ALGORITHM = \PASSWORD_DEFAULT;

    /** @var string Pepper usado no HMAC-SHA512 */
    private const PEPPER = 'bec95beffb3afd078df7cbfd4c4617ba214ac4641a157c1ca64106e7544c9fb4cef6e99b0a8f0b63e96328c09943ce96b9b8899ff54fa7ea57b622675442dbbf';

    /** @var string Prefixo indicando prehash + bcrypt */
    private const PREFIX_BCRYPT_PREHASH = '$pa01';

    /** @var int Tamanho do prefixo */
    private const PREFIX_LENGTH = 5;

    /**
     * Gera um hash seguro para o texto da senha.
     *
     * @param string $passwordText
     * @return string|bool
     */
    public static function from(string $passwordText) {
        $useBcrypt = self::usesBcrypt();

        if ($useBcrypt) {
            $passwordText = self::prehash($passwordText);
            $prefix = self::PREFIX_BCRYPT_PREHASH;
        }
        else {
            $prefix = '';
        }

        return $prefix . \password_hash($passwordText, self::HASH_ALGORITHM);
    }

    /**
     * Verifica se o texto da senha corresponde ao hash armazenado.
     *
     * @param string $passwordText
     * @param string $expectedHash
     * @return bool
     */
    public static function verify(string $passwordText, string $expectedHash): bool {
        $hasPrefix = self::hasPrehashPrefix($expectedHash);

        if ($hasPrefix) {
            $passwordText = self::prehash($passwordText);
            $expectedHash = self::removePrefix($expectedHash);
        }

        return \password_verify($passwordText, $expectedHash);
    }

    /**
     * Verifica se o hash existente precisa ser refeito.
     *
     * @param string $existingHash
     * @return bool
     */
    public static function needsRehash(string $existingHash): bool {
        if (self::hasPrehashPrefix($existingHash)) {
            $existingHash = self::removePrefix($existingHash);
        }

        return \password_needs_rehash($existingHash, self::HASH_ALGORITHM);
    }

    /**
     * Aplica prehash com HMAC-SHA512 + Base64.
     *
     * @param string $passwordText
     * @return string
     * @throws AuthError
     */
    private static function prehash(string $passwordText): string {
        $pepperBinary = \hex2bin(self::PEPPER);

        $hmacBinary = \hash_hmac('sha512', $passwordText, $pepperBinary, true);

        if (!$hmacBinary) {
            throw new AuthError('Could not generate HMAC');
        }

        return \base64_encode($hmacBinary);
    }

    /**
     * Verifica se o algoritmo atual é bcrypt.
     *
     * @return bool
     */
    private static function usesBcrypt(): bool {
        return self::HASH_ALGORITHM === \PASSWORD_BCRYPT
            || self::HASH_ALGORITHM === null;
    }

    /**
     * Verifica se o hash possui o prefixo de prehash.
     *
     * @param string $hash
     * @return bool
     */
    private static function hasPrehashPrefix(string $hash): bool {
        return \strncmp($hash, self::PREFIX_BCRYPT_PREHASH, self::PREFIX_LENGTH) === 0;
    }

    /**
     * Remove o prefixo do hash.
     *
     * @param string $hash
     * @return string
     */
    private static function removePrefix(string $hash): string {
        return \substr($hash, self::PREFIX_LENGTH);
    }
}
