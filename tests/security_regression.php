<?php

/**
 * Dependency-free regression checks for the v1.0.1 input-hardening (non-scalar/UTF-8 drop,
 * raw size cap). Each check names what it guards.
 *
 * Run:  php tests/security_regression.php   — exits non-zero on failure so it can gate CI.
 */

require __DIR__ . '/../src/WireFormat.php';
require __DIR__ . '/../src/Vector.php';

use Workmatrix\CohortVector\Vector;

// Promote every notice/warning to an exception so a stray "Array to string
// conversion" can never pass silently.
set_error_handler(static function (int $severity, string $message, string $file, int $line): bool {
    throw new \ErrorException($message, 0, $severity, $file, $line);
});

$failures = 0;
function check(string $name, callable $fn): void {
    global $failures;
    try {
        $fn();
        echo "  ok   $name\n";
    } catch (\Throwable $e) {
        $failures++;
        echo "  FAIL $name -- " . get_class($e) . ': ' . $e->getMessage() . "\n";
    }
}
function assertSame($expected, $actual, string $msg = ''): void {
    if ($expected !== $actual) {
        throw new \RuntimeException(($msg !== '' ? "$msg: " : '') . 'expected ' . json_encode($expected) . ', got ' . json_encode($actual));
    }
}

function b64url(string $s): string {
    return rtrim(strtr(base64_encode($s), '+/', '-_'), '=');
}

echo "Security regression checks:\n";

// Finding 1 & 3 — non-scalar values on allow-listed keys are dropped, no warning raised.
check('non-scalar array/object values are dropped on decode (no "Array" poisoning, no warning)', function () {
    $vector = b64url(json_encode(['source' => ['a', 'b'], 'locale' => ['x' => 'y'], '_v' => 1]));
    assertSame([], Vector::decode($vector));
});
check('non-scalar values are dropped on encode', function () {
    $r = Vector::encode(['source' => ['a', 'b'], 'adults' => 2]);
    assertSame(['adults' => '2'], $r['features']);
});

// Finding 2 — invalid UTF-8 is dropped instead of throwing out of encode()/merge().
check('invalid UTF-8 value is dropped, encode() does not throw', function () {
    $r = Vector::encode(['source' => "\xB1\x31bad", 'campaign' => 'spring']);
    assertSame(['campaign' => 'spring'], $r['features']);
});
check('invalid UTF-8 value is dropped, merge() does not throw', function () {
    $r = Vector::merge('', ['campaign' => "spring\xFF"]);
    assertSame([], $r['features']);
});

// Size cap — oversized raw vectors are rejected before base64/JSON decoding.
check('oversized vector is rejected by decode()/version() without decoding', function () {
    $oversized = str_repeat('A', \Workmatrix\CohortVector\WireFormat::MAX_VECTOR_LENGTH + 1);
    assertSame([], Vector::decode($oversized));
    assertSame(null, Vector::version($oversized));
});
check('a full-size legitimate vector is still accepted', function () {
    // Every allow-listed key at the max value length must round-trip (cap has headroom).
    $features = [];
    foreach (\Workmatrix\CohortVector\WireFormat::ALLOWED_KEYS as $k) {
        $features[$k] = str_repeat('x', \Workmatrix\CohortVector\WireFormat::MAX_VALUE_LENGTH);
    }
    $enc = Vector::encode($features);
    if (strlen($enc['vector']) > \Workmatrix\CohortVector\WireFormat::MAX_VECTOR_LENGTH) {
        throw new \RuntimeException('full vector (' . strlen($enc['vector']) . ' bytes) exceeds MAX_VECTOR_LENGTH');
    }
    assertSame($enc['features'], Vector::decode($enc['vector']), 'full vector round-trip');
});

// Regressions — the hardening must not change legitimate behaviour or byte-identity.
check('happy path: filtering, numeric cast, empty/bogus-key drop, ordering', function () {
    $r = Vector::encode(['source' => 'google', 'adults' => 2, 'campaign' => '', 'bogus' => 'x', 'locale' => 'de-DE']);
    assertSame(['adults' => '2', 'locale' => 'de-DE', 'source' => 'google'], $r['features']);
    assertSame($r['features'], Vector::decode($r['vector']), 'round-trip');
    assertSame(1, Vector::version($r['vector']));
});
check('valid multi-byte UTF-8 is preserved', function () {
    $r = Vector::encode(['locale' => '日本語', 'rooms' => 3]);
    assertSame(['locale' => '日本語', 'rooms' => '3'], $r['features']);
});

// Cross-repo conformance fixtures still hold (byte-identity contract).
check('conformance/vectors.json fixtures still pass', function () {
    $data  = json_decode(file_get_contents(__DIR__ . '/../conformance/vectors.json'), true);
    $cases = $data['cases'] ?? $data;
    foreach ($cases as $i => $c) {
        $enc = Vector::encode($c['input']);
        if (isset($c['vector'])) {
            assertSame($c['vector'], $enc['vector'], "case $i vector");
        }
        if (isset($c['features'])) {
            assertSame($c['features'], $enc['features'], "case $i features");
        }
    }
});

echo $failures === 0 ? "\nAll checks passed.\n" : "\n$failures check(s) FAILED.\n";
exit($failures === 0 ? 0 : 1);
