<?php

namespace Delight\Auth;

final class PasswordHash {

    private const HASH_ALGO = \PASSWORD_DEFAULT;
    private const PEPPER = 'bec95beffb3afd078df7cbfd4c4617ba214ac4641a157c1ca64106e7544c9fb4cef6e99b0a8f0b63e96328c09943ce96b9b8899ff54fa7ea57b622675442dbbf';
    private const PREFIX = '$pa01';
    private const PREFIX_LEN = 5;

    /**
     * Gera um hash seguro para a senha.
     *
     * @param string $password
     * @return string
     * @throws AuthError
     */
    public static function from(string $password): string {
        $usePrehash = self::shouldUsePrehash();

        if ($usePrehash) {
            $password = self::prehash($password);
        }

        $hash = \password_hash($password, self::HASH_ALGO);

        if ($hash === false) {
            throw new AuthError('Falha ao gerar hash da senha');
        }

        return ($usePrehash ? self::PREFIX : '') . $hash;
    }

    /**
     * Verifica se a senha corresponde ao hash armazenado.
     *
     * @param string $password
     * @param string $expectedHash
     * @return bool
     * @throws AuthError
     */
    public static function verify(string $password, string $expectedHash): bool {
        if (self::hasPrefix($expectedHash)) {
            $password = self::prehash($password);
            $expectedHash = self::stripPrefix($expectedHash);
        }

        return \password_verify($password, $expectedHash);
    }

    /**
     * Verifica se o hash precisa ser atualizado.
     *
     * @param string $hash
     * @return bool
     */
    public static function needsRehash(string $hash): bool {
        if (self::hasPrefix($hash)) {
            $hash = self::stripPrefix($hash);
        }

        return \password_needs_rehash($hash, self::HASH_ALGO);
    }

    /**
     * Aplica pré-hashing com HMAC-SHA512 + Base64.
     *
     * @param string $password
     * @return string
     * @throws AuthError
     */
    private static function prehash(string $password): string {
        $pepper = \hex2bin(self::PEPPER);

        if ($pepper === false) {
            throw new AuthError('Pepper inválido para HMAC');
        }

        $hmac = \hash_hmac('sha512', $password, $pepper, true);

        if (empty($hmac)) {
            throw new AuthError('Falha ao gerar HMAC para pré-hash');
        }

        return \base64_encode($hmac);
    }

    /**
     * Determina se o pré-hash deve ser aplicado.
     */
    private static function shouldUsePrehash(): bool {
        return self::HASH_ALGO === \PASSWORD_BCRYPT || self::HASH_ALGO === null;
    }

    /**
     * Verifica se o hash possui o prefixo customizado.
     */
    private static function hasPrefix(string $hash): bool {
        return \strncmp($hash, self::PREFIX, self::PREFIX_LEN) === 0;
    }

    /**
     * Remove o prefixo customizado do hash.
     */
    private static function stripPrefix(string $hash): string {
        return \substr($hash, self::PREFIX_LEN);
    }
}
