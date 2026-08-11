<?php

namespace Delight\Auth;

final class PasswordHash
{
    private const HASH_ALGO = \PASSWORD_DEFAULT;
    private const PEPPER = 'bec95beffb3afd078df7cbfd4c4617ba214ac4641a157c1ca64106e7544c9fb4cef6e99b0a8f0b63e96328c09943ce96b9b8899ff54fa7ea57b622675442dbbf';
    private const PREFIX = '$pa01';
    private const PREFIX_LEN = 5;

    /**
     * Gera um hash seguro para o texto da senha.
     */
    public static function from(string $password): string
    {
        $useBcrypt = self::HASH_ALGO === \PASSWORD_BCRYPT || self::HASH_ALGO === null;

        if ($useBcrypt) {
            $password = self::prehash($password);
            $prefix = self::PREFIX;
        } else {
            $prefix = '';
        }

        return $prefix . \password_hash($password, self::HASH_ALGO);
    }

    /**
     * Verifica se o texto da senha corresponde ao hash armazenado.
     */
    public static function verify(string $password, string $expectedHash): bool
    {
        if (self::hasPrefix($expectedHash)) {
            $password = self::prehash($password);
            $expectedHash = self::stripPrefix($expectedHash);
        }

        return \password_verify($password, $expectedHash);
    }

    /**
     * Verifica se o hash precisa ser refeito.
     */
    public static function needsRehash(string $hash): bool
    {
        if (self::hasPrefix($hash)) {
            $hash = self::stripPrefix($hash);
        }

        return \password_needs_rehash($hash, self::HASH_ALGO);
    }

    /**
     * Aplica HMAC + Base64 para pré-hash seguro.
     */
    private static function prehash(string $password): string
    {
        $pepper = \hex2bin(self::PEPPER);

        if ($pepper === false) {
            throw new AuthError('Pepper inválido');
        }

        $hmac = \hash_hmac('sha512', $password, $pepper, true);

        if (empty($hmac)) {
            throw new AuthError('Falha ao gerar HMAC');
        }

        return \base64_encode($hmac);
    }

    /**
     * Verifica se o hash contém o prefixo customizado.
     */
    private static function hasPrefix(string $hash): bool
    {
        return \strncmp($hash, self::PREFIX, self::PREFIX_LEN) === 0;
    }

    /**
     * Remove o prefixo customizado do hash.
     */
    private static function stripPrefix(string $hash): string
    {
        return \substr($hash, self::PREFIX_LEN);
    }
}
