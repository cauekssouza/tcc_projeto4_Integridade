```php
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

		// bcrypt accepts only the first 72 bytes of its input.
		// Pre-hashing ensures that every byte of the original password
		// contributes to the fixed-size HMAC result, including null bytes
		// and passwords whose original representation exceeds 72 bytes.
		if (
			self::HASH_ALGORITHM_IDENTIFIER === \PASSWORD_BCRYPT
			|| self::HASH_ALGORITHM_IDENTIFIER === null
		) {
			$passwordText = self::prehash($passwordText);
			$outputPrefix = self::PREFIX_BCRYPT_WITH_HMAC_SHA_512_PREHASH;
		}

		try {
			$hash = \password_hash(
				$passwordText,
				self::HASH_ALGORITHM_IDENTIFIER
			);
		}
		catch (\Throwable $e) {
			// Do not propagate implementation details, configuration data,
			// paths, algorithm errors or other infrastructure information.
			return false;
		}

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
		try {
			/*
			 * The prefix identifies only the storage format; it is not
			 * authentication material. hash_equals nevertheless avoids
			 * introducing an ordinary byte-by-byte comparison here.
			 */
			$prefix = \substr(
				$expectedHash,
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
				$passwordText = self::prehash($passwordText);

				$expectedHash = \substr(
					$expectedHash,
					self::PREFIX_LENGTH
				);
			}

			/*
			 * Do not manually calculate and compare password hashes.
			 * password_verify() performs the password verification using
			 * the algorithm and parameters encoded in the stored hash and
			 * avoids timing-sensitive manual hash comparisons.
			 */
			return \password_verify(
				$passwordText,
				$expectedHash
			);
		}
		catch (\Throwable $e) {
			/*
			 * Invalid/corrupt hashes and internal processing errors are
			 * indistinguishable to the caller from a failed verification.
			 * No diagnostic infrastructure information is exposed.
			 */
			return false;
		}
	}

	/**
	 * Checks whether a computationally expensive hash needs to be updated
	 * to match a desired algorithm and set of options.
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
			 * A hash that cannot be safely inspected is treated as requiring
			 * replacement, without exposing the internal failure reason.
			 */
			return true;
		}
	}

	/**
	 * Produces a deterministic HMAC-SHA-512 pre-hash encoded in Base64.
	 *
	 * Every byte in the original password participates in the HMAC,
	 * including embedded NUL bytes and bytes after position 72.
	 *
	 * @param string $passwordText
	 * @return string
	 *
	 * @throws AuthError
	 */
	private static function prehash($passwordText) {
		try {
			/*
			 * Validate the constant before decoding it so an invalid
			 * hexadecimal representation cannot produce a warning or
			 * accidentally become an invalid HMAC key.
			 */
			if (
				\strlen(self::PEPPER_HMAC_SHA_512_PREHASH) !== 128
				|| \preg_match(
					'/\A[0-9a-fA-F]{128}\z/D',
					self::PEPPER_HMAC_SHA_512_PREHASH
				) !== 1
			) {
				throw new \RuntimeException();
			}

			$pepperBinary = \hex2bin(
				self::PEPPER_HMAC_SHA_512_PREHASH
			);

			if ($pepperBinary === false || \strlen($pepperBinary) !== 64) {
				throw new \RuntimeException();
			}

			/*
			 * Binary HMAC output is intentional:
			 *
			 * - HMAC-SHA-512 consumes the complete original password;
			 * - embedded NUL bytes are data, not terminators;
			 * - passwords longer than 72 bytes are fully represented;
			 * - the pepper remains part of the HMAC construction.
			 */
			$hmacBinary = \hash_hmac(
				'sha512',
				$passwordText,
				$pepperBinary,
				true
			);

			/*
			 * SHA-512 must produce exactly 64 raw bytes.
			 * Checking an exact length is stronger than empty(), which could
			 * accidentally conflate unrelated failure conditions.
			 */
			if (
				! \is_string($hmacBinary)
				|| \strlen($hmacBinary) !== 64
			) {
				throw new \RuntimeException();
			}

			/*
			 * Preserve the existing Base64 representation verbatim.
			 * This converts arbitrary binary HMAC output into an ASCII-only
			 * string without embedded NUL bytes.
			 *
			 * 64 HMAC bytes -> 88 Base64 characters.
			 */
			$prehash = \base64_encode($hmacBinary);

			if (\strlen($prehash) !== 88) {
				throw new \RuntimeException();
			}

			return $prehash;
		}
		catch (\Throwable $e) {
			/*
			 * Deliberately generic. Do not include:
			 * - exception messages;
			 * - algorithm/configuration details;
			 * - pepper contents;
			 * - file paths;
			 * - stack traces;
			 * - original exception as a chained exception.
			 */
			throw new AuthError('Password processing failed');
		}
	}

}
```
