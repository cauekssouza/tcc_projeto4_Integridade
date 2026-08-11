<?php

namespace Delight\Auth;

final class PasswordHash {

    /** @var int|string Algoritmo principal de hashing */
    private const HASH_ALGO = \PASSWORD_DEFAULT;

    /** @var string Pepper semipública usada no HMAC */
    private const PEPPER = 'bec95beffb3afd078df7cbfd4c4617ba214ac4641a157c1ca64106e7544c9fb4cef6e99b0a8f0b63e96328c09943ce96b9b8899ff54fa7ea57b622675442dbbf';

    /** @var string Prefixo indicando uso de pre-hash */
    private const PREFIX = '$pa01';

    /** @var int Tamanho do prefixo */
    private const PREFIX_LEN = 5;

    /**
     * Gera o hash seguro da senha
     *
     * @param string $password
     * @return string
     * @throws AuthError
     */
    public static function from(string $password): string {
        $useBcrypt = self::HASH_ALGO === \PASSWORD_BCRYPT || self::HASH_ALGO === null;

        if ($useBcrypt) {
            $password = self::prehash($password);
            return self::PREFIX . \password_hash($password, self::HASH_ALGO);
        }

        return \password_hash($password, self::HASH_ALGO);
    }

    /**
     * Verifica se a senha corresponde ao hash
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
     * Verifica se o hash precisa ser atualizado
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
     * Aplica pre-hash com HMAC-SHA512 + Base64
     *
     * @param string $password
     * @return string
     * @throws AuthError
     */
    private static function prehash(string $password): string {
        $pepper = \hex2bin(self::PEPPER);

        if ($pepper === false) {
            throw new AuthError('Pepper inválida ou corrompida');
        }

        $hmac = \hash_hmac('sha512', $password, $pepper, true);

        if (!$hmac) {
            throw new AuthError('Falha ao gerar HMAC para pre-hash');
        }

        return \base64_encode($hmac);
    }

    /**
     * Verifica se o hash possui o prefixo customizado
     */
    private static function hasPrefix(string $hash): bool {
        return \strncmp($hash, self::PREFIX, self::PREFIX_LEN) === 0;
    }

    /**
     * Remove o prefixo customizado
     */
    private static function stripPrefix(string $hash): string {
        return \substr($hash, self::PREFIX_LEN);
    }
}
