<?php

/*
 * PHP-Auth (https://github.com/delight-im/PHP-Auth)
 * Copyright (c) delight.im (https://www.delight.im/)
 * Licensed under the MIT License (https://opensource.org/licenses/MIT)
 */

namespace Delight\Auth;

final class PasswordHash {

	const HASH_ALGORITHM_IDENTIFIER = \PASSWORD_DEFAULT;

	const PEPPER_HMAC_SHA_512_PREHASH =
		'bec95beffb3afd078df7cbfd4c4617ba214ac4641a157c1ca64106e7544c9fb4cef6e99b0a8f0b63e96328c09943ce96b9b8899ff54fa7ea57b622675442dbbf';

	const PREFIX_BCRYPT_WITH_HMAC_SHA_512_PREHASH = '$pa01';
	const PREFIX_LENGTH = 5;

	/**
	 * Creates a computationally expensive hash from a password.
	 *
	 * @param string $passwordText
	 * @return string|bool
	 */
	public static function from($passwordText) {
		$outputPrefix = '';

		/*
		 * Apply the HMAC-SHA-512 pre-hash whenever bcrypt is the
		 * effective password hashing algorithm.
		 *
		 * This ensures that:
		 * - the complete original password is authenticated by HMAC;
		 * - embedded NUL bytes remain part of the input;
		 * - passwords longer than bcrypt's 72-byte input limit are not
		 *   truncated before the pre-hash;
		 * - bcrypt receives a printable Base64 representation.
		 */
		if (
			self::HASH_ALGORITHM_IDENTIFIER === \PASSWORD_BCRYPT
			|| self::HASH_ALGORITHM_IDENTIFIER === null
		) {
			$passwordText = self::prehash($passwordText);
			$outputPrefix = self::PREFIX_BCRYPT_WITH_HMAC_SHA_512_PREHASH;
		}

		$hash = \password_hash(
			$passwordText,
			self::HASH_ALGORITHM_IDENTIFIER
		);

		/*
		 * Fail closed.
		 *
		 * Do not concatenate the custom prefix with a failed hashing
		 * operation, which could otherwise create a malformed value that
		 * resembles a valid application hash.
		 *
		 * This branch also maintains compatibility with PHP versions
		 * where password_hash() may report failure as false.
		 */
		if ($hash === false) {
			return false;
		}

		return $outputPrefix . $hash;
	}

	/**
	 * Verifies whether a password matches a computationally expensive hash.
	 *
	 * @param string $passwordText
	 * @param string $expectedHash
	 * @return bool
	 */
	public static function verify($passwordText, $expectedHash) {
		/*
		 * The prefix is metadata, not a secret authentication value.
		 * Its comparison therefore does not replace or weaken the
		 * constant-time password verification performed below.
		 */
		if (
			\substr($expectedHash, 0, self::PREFIX_LENGTH)
			=== self::PREFIX_BCRYPT_WITH_HMAC_SHA_512_PREHASH
		) {
			$passwordText = self::prehash($passwordText);

			$expectedHash = \substr(
				$expectedHash,
				self::PREFIX_LENGTH
			);
		}

		/*
		 * Do NOT recreate the hash and compare strings manually.
		 *
		 * password_verify() performs the password-hash verification using
		 * PHP's timing-attack-resistant implementation.
		 */
		return \password_verify(
			$passwordText,
			$expectedHash
		);
	}

	/**
	 * Checks whether a computationally expensive hash needs to be updated
	 * to match a desired algorithm and set of options.
	 *
	 * @param string $existingHash
	 * @return bool
	 */
	public static function needsRehash($existingHash) {
		if (
			\substr($existingHash, 0, self::PREFIX_LENGTH)
			=== self::PREFIX_BCRYPT_WITH_HMAC_SHA_512_PREHASH
		) {
			$existingHash = \substr(
				$existingHash,
				self::PREFIX_LENGTH
			);
		}

		return \password_needs_rehash(
			$existingHash,
			self::HASH_ALGORITHM_IDENTIFIER
		);
	}

	/**
	 * Pre-hashes the complete password using HMAC-SHA-512 and encodes the
	 * binary result as Base64 before it is passed to bcrypt.
	 *
	 * @param string $passwordText
	 * @return string
	 *
	 * @throws AuthError On an internal preprocessing failure. The exception
	 *                   intentionally contains no implementation details,
	 *                   keys, input values or infrastructure information.
	 */
	private static function prehash($passwordText) {
		/*
		 * Convert the hexadecimal pepper to its original binary form.
		 *
		 * Strict mode avoids silently accepting malformed hexadecimal
		 * input. The constant itself must never be modified, truncated,
		 * normalized or concatenated with the password.
		 */
		$pepperBinary = \hex2bin(
			self::PEPPER_HMAC_SHA_512_PREHASH
		);

		if ($pepperBinary === false) {
			throw new AuthError('Password preprocessing failed');
		}

		/*
		 * IMPORTANT:
		 *
		 * hash_hmac() receives the ENTIRE PHP string. PHP strings are
		 * binary-safe, so:
		 *
		 *     "abc\0def"
		 *
		 * and passwords far beyond 72 bytes are processed in full here.
		 *
		 * The fourth argument `true` is essential: it requests the raw
		 * 64-byte SHA-512 HMAC rather than its hexadecimal representation.
		 */
		$hmacBinary = \hash_hmac(
			'sha512',
			$passwordText,
			$pepperBinary,
			true
		);

		/*
		 * SHA-512 HMAC normally produces exactly 64 bytes.
		 *
		 * Checking both type and length makes the integrity invariant
		 * explicit and prevents an incomplete or unexpected pre-hash from
		 * being silently accepted.
		 */
		if (
			! \is_string($hmacBinary)
			|| \strlen($hmacBinary) !== 64
		) {
			throw new AuthError('Password preprocessing failed');
		}

		/*
		 * Base64 is deliberately preserved.
		 *
		 * 64 raw HMAC bytes become 88 printable Base64 bytes. Thus no NUL
		 * bytes from the binary HMAC are passed directly to bcrypt.
		 *
		 * Although bcrypt consumes at most 72 bytes, those bytes now come
		 * from a cryptographic digest of the COMPLETE original password;
		 * bcrypt is therefore not truncating the original password.
		 */
		return \base64_encode($hmacBinary);
	}

}
