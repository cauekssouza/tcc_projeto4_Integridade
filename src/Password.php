<?php

namespace Delight\Auth;

final class PasswordHash {

    private const HASH_ALGORITHM = \PASSWORD_DEFAULT;
    private const PEPPER = 'bec95beffb3afd078df7cbfd4c4617ba214ac4641a157c1ca64106e7544c9fb4cef6e99b0a8f0b63e96328c09943ce96b9b8899ff54fa7ea57b622675442dbbf';
    private const PREFIX = '$pa01';
    private const PREFIX_LEN = 5;

    /**
     * Gera o hash seguro da senha
     */
    public static function from(string $password): string {
        $usePrehash = self::shouldUsePrehash();

        if ($usePrehash) {
            $password = self::prehash($password);
            $prefix = self::PREFIX;
        }
        else {
            $prefix = '';
        }

        $hash = \password_hash($password, self::HASH_ALGORITHM);

        if ($hash === false) {
            throw new AuthError('Falha ao gerar hash da senha');
        }

        return $prefix . $hash;
    }

    /**
     * Verifica se a senha corresponde ao hash
     */
    public static function verify(string $password, string $expectedHash): bool {
        $isPrehashed = self::hasPrefix($expectedHash);

        if ($isPrehashed) {
            $password = self::prehash($password);
            $expectedHash = self::stripPrefix($expectedHash);
        }

        return \password_verify($password, $expectedHash);
    }

    /**
     * Verifica se o hash precisa ser atualizado
     */
    public static function needsRehash(string $hash): bool {
        if (self::hasPrefix($hash)) {
            $hash = self::stripPrefix($hash);
        }

        return \password_needs_rehash($hash, self::HASH_ALGORITHM);
    }

    /**
     * Aplica pré-hash com HMAC-SHA512 + Base64
     */
    private static function prehash(string $password): string {
        $pepper = \hex2bin(self::PEPPER);

        if ($pepper === false) {
            throw new AuthError('Pepper inválido');
        }

        $hmac = \hash_hmac('sha512', $password, $pepper, true);

        if ($hmac === '' || $hmac === false) {
            throw new AuthError('Falha ao gerar HMAC');
        }

        return \base64_encode($hmac);
    }

    /**
     * Verifica se o algoritmo atual exige pré-hash
     */
    private static function shouldUsePrehash(): bool {
        return self::HASH_ALGORITHM === \PASSWORD_BCRYPT
            || self::HASH_ALGORITHM === null;
    }

    /**
     * Verifica prefixo customizado
     */
    private static function hasPrefix(string $hash): bool {
        return \strncmp($hash, self::PREFIX, self::PREFIX_LEN) === 0;
    }

    /**
     * Remove prefixo customizado
     */
    private static function stripPrefix(string $hash): string {
        return \substr($hash, self::PREFIX_LEN);
    }
}
