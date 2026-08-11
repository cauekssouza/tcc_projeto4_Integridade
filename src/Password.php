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
	 * Creates a computationally expensive hash from a password
	 *
	 * @param string $passwordText
	 * @return string|bool
	 */
	public static function from($passwordText) {
		try {
			// When bcrypt is used, pre-hash the complete password first.
			// This prevents bcrypt's 72-byte input limit and null-byte
			// restrictions from changing the effective password.
			if (
				self::HASH_ALGORITHM_IDENTIFIER === \PASSWORD_BCRYPT
				|| self::HASH_ALGORITHM_IDENTIFIER === null
			) {
				$passwordText = self::prehash($passwordText);
				$outputPrefix = self::PREFIX_BCRYPT_WITH_HMAC_SHA_512_PREHASH;
			}
			else {
				$outputPrefix = '';
			}

			$hash = \password_hash(
				$passwordText,
				self::HASH_ALGORITHM_IDENTIFIER
			);

			// Preserve the documented string|bool return contract.
			if ($hash === false) {
				return false;
			}

			return $outputPrefix . $hash;
		}
		catch (AuthError $e) {
			// prehash() already converted the failure into a sanitized error.
			throw $e;
		}
		catch (\Throwable $e) {
			// Never propagate implementation, algorithm or infrastructure
			// details originating from PHP internals.
			throw new AuthError('Password processing failed');
		}
	}

	/**
	 * Verifies whether a password matches a computationally expensive hash
	 *
	 * @param string $passwordText
	 * @param string $expectedHash
	 * @return bool
	 */
	public static function verify($passwordText, $expectedHash) {
		try {
			/*
			 * Always extract exactly PREFIX_LENGTH bytes before comparing.
			 *
			 * hash_equals() prevents introducing a conventional early-exit
			 * string comparison into the authentication path.
			 *
			 * The prefix itself is not secret, but using a timing-safe
			 * primitive here keeps comparisons in verify() consistently
			 * resistant to timing discrepancies.
			 */
			$prefix = \substr(
				$expectedHash,
				0,
				self::PREFIX_LENGTH
			);

			$usesPrehash =
				\strlen($prefix) === self::PREFIX_LENGTH
				&& \hash_equals(
					self::PREFIX_BCRYPT_WITH_HMAC_SHA_512_PREHASH,
					$prefix
				);

			if ($usesPrehash) {
				$passwordText = self::prehash($passwordText);

				$expectedHash = \substr(
					$expectedHash,
					self::PREFIX_LENGTH
				);
			}

			/*
			 * Do NOT calculate another hash and compare strings manually.
			 *
			 * password_verify() performs the password-hash verification
			 * using PHP's timing-attack-safe implementation.
			 */
			return \password_verify(
				$passwordText,
				$expectedHash
			);
		}
		catch (\Throwable $e) {
			/*
			 * Authentication failure is intentionally indistinguishable
			 * from malformed/unusable hash data.
			 *
			 * No internal exception text escapes this boundary.
			 */
			return false;
		}
	}

	/**
	 * Checks whether a computationally expensive hash needs to be updated
	 * to match a desired algorithm and set of options
	 *
	 * @param string $existingHash
	 * @return bool
	 */
	public static function needsRehash($existingHash) {
		try {
			$prefix = \substr(
				$existingHash,
				0,
				self::PREFIX_LENGTH
			);

			if (
				\strlen($prefix) === self::PREFIX_LENGTH
				&& \hash_equals(
					self::PREFIX_BCRYPT_WITH_HMAC_SHA_512_PREHASH,
					$prefix
				)
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
		catch (\Throwable $e) {
			/*
			 * An unreadable/invalid hash should be replaced rather than
			 * exposing the cause of the failure.
			 */
			return true;
		}
	}

	/**
	 * Produces a fixed-format representation of the complete password.
	 *
	 * HMAC-SHA-512:
	 *   input  = original password, including NUL bytes and all bytes > 72
	 *   key    = binary representation of the fixed pepper
	 *   output = 64 raw bytes
	 *
	 * Base64:
	 *   converts those 64 bytes into an ASCII-only representation,
	 *   preventing embedded NUL bytes from reaching bcrypt.
	 *
	 * @param string $passwordText
	 * @return string
	 * @throws AuthError
	 */
	private static function prehash($passwordText) {
		try {
			/*
			 * Decode the hexadecimal pepper without modifying, truncating,
			 * concatenating or otherwise normalizing its contents.
			 */
			$pepperBinary = \hex2bin(
				self::PEPPER_HMAC_SHA_512_PREHASH
			);

			/*
			 * A SHA-512 pepper encoded as hexadecimal must decode to exactly
			 * 64 bytes. Use strict checks instead of empty(), avoiding
			 * type-coercion ambiguity.
			 */
			if (
				$pepperBinary === false
				|| \strlen($pepperBinary) !== 64
			) {
				throw new AuthError('Password processing failed');
			}

			/*
			 * Process the ENTIRE password as binary-safe input.
			 *
			 * hash_hmac() receives the string length maintained by PHP,
			 * therefore embedded "\0" bytes do not terminate the password,
			 * and input beyond 72 bytes is incorporated into the HMAC.
			 */
			$hmacBinary = \hash_hmac(
				'sha512',
				$passwordText,
				$pepperBinary,
				true
			);

			/*
			 * SHA-512 HMAC in raw mode must contain exactly 64 bytes.
			 * Never use empty() for cryptographic binary values.
			 */
			if (
				!\is_string($hmacBinary)
				|| \strlen($hmacBinary) !== 64
			) {
				throw new AuthError('Password processing failed');
			}

			/*
			 * Preserve Base64 exactly.
			 *
			 * 64 bytes of HMAC-SHA-512 become 88 ASCII Base64 bytes.
			 * This eliminates embedded NUL bytes before bcrypt.
			 */
			return \base64_encode($hmacBinary);
		}
		catch (AuthError $e) {
			// Already sanitized: no low-level diagnostic information.
			throw $e;
		}
		catch (\Throwable $e) {
			/*
			 * Do not expose PHP exception messages, algorithm names,
			 * paths, configuration or other environmental information.
			 */
			throw new AuthError('Password processing failed');
		}
	}

}
