# workmatrix/cohort-vector

Shared, dependency-free PHP codec for the **Cohort-Vector** — the cohort fingerprint the
Workmatrix booking-engine frontend (IBE) and the station backend exchange on the
`Cohort-Vector` HTTP header.

Both sides depend on this one package so they encode and decode **byte-identical** vectors.
It has no runtime dependencies beyond `ext-json` and `ext-mbstring`.

## Install

```jsonc
// composer.json
{
  "repositories": [
    { "type": "vcs", "url": "https://github.com/workmatrix/cohort-vector" }
  ],
  "require": {
    "workmatrix/cohort-vector": "^1.0"
  }
}
```

```bash
composer require workmatrix/cohort-vector
```

## Usage

```php
use Workmatrix\CohortVector\Vector;
use Workmatrix\CohortVector\WireFormat;

// Encode the features you know into the header value:
$result = Vector::encode([
    'source'  => 'google',
    'device'  => 'mobile',
    'locale'  => 'de-CH',
    'adults'  => 2,
    'stayNights' => 3,
]);
$headerValue = $result['vector'];   // send as: Cohort-Vector: <value>
$canonical   = $result['features']; // the filtered, canonical feature map

// Decode an incoming header:
$features = Vector::decode($request->getHeaderLine('Cohort-Vector'));

// Incrementally update a vector you already hold (null removes a key):
$updated = Vector::merge($headerValue, ['campaign' => 'summer', 'content' => null]);
```

## What it carries

The allow-list is the single source of truth in `WireFormat::ALLOWED_KEYS`. Anything not on
it is silently dropped on both encode and decode. Currently:

| Group | Keys |
|---|---|
| Acquisition / client signals | `source`, `medium`, `campaign`, `content`, `locale`, `channel`, `country`, `market`, `device` |
| Occupancy | `adults`, `children`, `rooms` |
| Derived cohort values | `stayNights`, `leadTimeDays` |

Deliberately **never** carried: raw `stayDates` (would make the vector session-specific
rather than a cohort fingerprint). Values are stored as strings on the wire; consumers that
match on numerics should int-coerce on read.

## Wire format

```
features → keep allowed keys → drop null/empty & values >200 chars → stamp _v → ksort → json_encode → base64url
```

The reserved `_v` key carries `WireFormat::VERSION` inside the JSON. It is **never** a feature:
`encode()` stamps it only into the payload, and `decode()` strips it. The decoder tolerates a
missing/older/newer `_v` (it re-canonicalizes from the surviving allow-listed keys), so the two
repos can deploy independently. Bump `WireFormat::VERSION` only when the encoding rules change.

## Cross-repo conformance

`conformance/vectors.json` holds `{input → features, vector}` fixtures. **Every consumer's test
suite must assert it reproduces each `vector` exactly** — this is the guard against the two
codecs silently drifting apart. Regenerate the fixtures only when `WireFormat::VERSION` changes.
