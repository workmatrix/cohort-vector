<?php

namespace Workmatrix\CohortVector;

final class Vector {

	/**
	 * Encode features into a deterministic base64url vector string.
	 *
	 * Filters to allowed keys, removes nulls, sorts by key, JSON-encodes, base64url-encodes.
	 *
	 * @param  array<string, mixed> $features
	 * @return array{vector: string, features: array<string, string>} The encoded vector and the canonical features used
	 */
	public static function encode(array $features): array {
		$filtered = self::filterFeatures($features);

		// Stamp the version only into the JSON payload — never into the returned features,
		// so `_v` cannot leak into the feature set handlers/RulesEngine/observability see.
		$payload = $filtered + [WireFormat::VERSION_KEY => WireFormat::VERSION];
		ksort($payload);

		$json   = json_encode($payload, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
		$vector = self::base64urlEncode($json);

		return ['vector' => $vector, 'features' => $filtered];
	}

	/**
	 * Decode a vector string back into features.
	 *
	 * @param  string $vector The base64url-encoded vector
	 * @return array<string, string> The decoded features (already filtered and sorted)
	 */
	public static function decode(string $vector): array {
		// Bound work on untrusted input: reject oversized headers before any decoding.
		if (strlen($vector) > WireFormat::MAX_VECTOR_LENGTH) {
			return [];
		}

		$json = self::base64urlDecode($vector);
		if ($json === false) {
			return [];
		}

		$features = json_decode($json, true);
		if (!is_array($features)) {
			return [];
		}

		// Re-filter on decode to guard against tampered vectors. This also drops the
		// reserved version key, so `_v` never reaches handlers/RulesEngine as a feature.
		return self::filterFeatures($features);
	}

	/**
	 * Read the wire-format version stamped in a vector, or null if absent/undecodable.
	 *
	 * Informational only — decode() tolerates any version. Useful for telemetry and for
	 * the consumer to detect when its codec package has drifted from the server's.
	 */
	public static function version(string $vector): ?int {
		if (strlen($vector) > WireFormat::MAX_VECTOR_LENGTH) {
			return null;
		}

		$json = self::base64urlDecode($vector);
		if ($json === false) {
			return null;
		}

		$decoded = json_decode($json, true);
		if (!is_array($decoded) || !isset($decoded[WireFormat::VERSION_KEY])) {
			return null;
		}

		return (int)$decoded[WireFormat::VERSION_KEY];
	}

	/**
	 * Merge new features into an existing vector.
	 *
	 * A null value in $updates removes that key from the result.
	 *
	 * @param  string               $existingVector The current vector (may be empty)
	 * @param  array<string, mixed> $updates        New features to merge
	 * @return array{vector: string, features: array<string, string>}
	 */
	public static function merge(string $existingVector, array $updates): array {
		$existing = $existingVector !== '' ? self::decode($existingVector) : [];

		// Apply updates — null means remove the key
		foreach ($updates as $key => $value) {
			if ($value === null) {
				unset($existing[$key]);
			} else {
				$existing[$key] = $value;
			}
		}

		return self::encode($existing);
	}

	/**
	 * Filter to allowed keys, drop null/empty/non-scalar/malformed/over-length values, sort by key.
	 *
	 * Input may be attacker-controlled (decode() passes untrusted JSON straight in), so anything
	 * that is not a clean, in-range UTF-8 scalar is silently dropped rather than allowed to fail.
	 *
	 * @param  array<string, mixed> $features
	 * @return array<string, string>
	 */
	private static function filterFeatures(array $features): array {
		$filtered = [];
		foreach ($features as $key => $value) {
			if (!in_array($key, WireFormat::ALLOWED_KEYS, true) || $value === null || $value === '') {
				continue;
			}

			// A non-scalar would cast to the literal "Array" and raise a conversion warning.
			if (!is_scalar($value)) {
				continue;
			}

			$str = (string)$value;

			// Malformed UTF-8 would make json_encode() throw under JSON_THROW_ON_ERROR in encode().
			if (!mb_check_encoding($str, 'UTF-8')) {
				continue;
			}

			if (mb_strlen($str) <= WireFormat::MAX_VALUE_LENGTH) {
				$filtered[$key] = $str;
			}
		}
		ksort($filtered);
		return $filtered;
	}

	private static function base64urlEncode(string $data): string {
		return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
	}

	private static function base64urlDecode(string $data): string|false {
		return base64_decode(strtr($data, '-_', '+/'), true);
	}
}
