<?php

namespace Workmatrix\CohortVector;

/**
 * Single source of truth for the Cohort-Vector wire format.
 *
 * Both the station backend and the booking-engine frontend depend on this package,
 * so the allow-list and limits live here and nowhere else.
 */
final class WireFormat {

	/**
	 * Wire-format version, stamped into every encoded vector under the reserved version key.
	 *
	 * Bump this when the encoding rules change in a way the other side must be aware of.
	 * The decoder tolerates a missing/older/newer version: it re-canonicalizes from the
	 * surviving allow-listed keys regardless, so a version mismatch degrades gracefully.
	 */
	public const VERSION = 1;

	/**
	 * Reserved key carrying the wire-format version inside the encoded JSON.
	 *
	 * It is never a feature and never a predicate — it is stripped on decode and never
	 * leaks into the feature set handed to handlers, RulesEngine, or observability.
	 */
	public const VERSION_KEY = '_v';

	/** Maximum length per string feature value — anything longer is silently dropped. */
	public const MAX_VALUE_LENGTH = 200;

	/**
	 * Keys allowed in the vector — anything else is silently dropped.
	 *
	 * Values are stored as strings (numbers are cast); RulesEngine int-coerces numeric
	 * keys on read, so no type machinery is needed here.
	 *
	 * Deliberately excluded: raw `stayDates` (would make the vector session-specific, not a
	 * cohort fingerprint) and `bookingDOW` (currently a wall-clock value — see the design doc).
	 */
	public const ALLOWED_KEYS = [
		// Acquisition + client signals
		'source',
		'medium',
		'campaign',
		'content',
		'locale',
		'channel',
		'country',  // consumer-provided override for IP geolocation
		'market',   // consumer-provided override for IP-derived market
		'device',   // device type (desktop, mobile, tablet)
		// Occupancy
		'adults',
		'children',
		'rooms',
		// Derived situational values — carried as cohort VALUES, never raw dates.
		// Recomputed and overwritten whenever a request carries arrival/departure;
		// used as-is on pages that don't (e.g. add-ons), so context survives navigation.
		'stayNights',
		'leadTimeDays',
	];
}
