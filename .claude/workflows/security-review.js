export const meta = {
  name: 'security-review',
  description: 'Thorough multi-agent security review: recon, parallel per-dimension review, adversarial verification of each finding, synthesized severity-ranked report',
  phases: [
    { title: 'Recon',  detail: 'map entry points, untrusted-input surfaces, deps, secrets, config' },
    { title: 'Review', detail: 'one agent per security dimension' },
    { title: 'Verify', detail: 'three skeptics per finding refute it; majority kills it' },
    { title: 'Report', detail: 'synthesize confirmed findings into a ranked report' },
  ],
}

const ROOT = (args && args.path) || '.'

const RECON_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['summary', 'languages', 'entryPoints', 'untrustedInputs', 'dependencies'],
  properties: {
    summary:         { type: 'string', description: 'What the project is, in 2-3 sentences' },
    languages:       { type: 'array', items: { type: 'string' } },
    entryPoints:     { type: 'array', items: { type: 'string' }, description: 'file:symbol of public/reachable entry points' },
    untrustedInputs: { type: 'array', items: { type: 'string' }, description: 'where external/untrusted data enters (parsers, request handlers, deserialization)' },
    sinks:           { type: 'array', items: { type: 'string' }, description: 'dangerous sinks: exec, eval, SQL, file I/O, network, header writes' },
    crypto:          { type: 'array', items: { type: 'string' }, description: 'crypto/secret/randomness usage, or empty if none' },
    dependencies:    { type: 'array', items: { type: 'string' }, description: 'runtime deps and lockfile/pinning status' },
    config:          { type: 'array', items: { type: 'string' }, description: 'security-relevant config / CI / build files' },
  },
}

const FINDINGS_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['findings'],
  properties: {
    findings: {
      type: 'array',
      items: {
        type: 'object',
        additionalProperties: false,
        required: ['title', 'severity', 'location', 'impact', 'rationale', 'remediation'],
        properties: {
          title:       { type: 'string' },
          severity:    { type: 'string', enum: ['critical', 'high', 'medium', 'low', 'info'] },
          location:    { type: 'string', description: 'file:line' },
          impact:      { type: 'string', description: 'concrete consequence if exploited' },
          rationale:   { type: 'string', description: 'why this is real: the code path / exploit sketch' },
          remediation: { type: 'string' },
        },
      },
    },
    checkedClean: { type: 'array', items: { type: 'string' }, description: 'things examined and found safe (so coverage is visible)' },
  },
}

const VERDICT_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['refuted', 'reason'],
  properties: {
    refuted: { type: 'boolean', description: 'true if the finding is wrong, not exploitable, or not reachable' },
    reason:  { type: 'string' },
  },
}

const DIMENSIONS = [
  { key: 'input-injection', title: 'Untrusted input & injection',
    prompt: 'Untrusted-input handling and injection. Trace every external input to its sink. Look for: unsafe deserialization/parsing, SQL/command/path/header injection, XSS, type confusion, missing input validation, base64/JSON decode pitfalls (strictness, type guards). For a codec, scrutinize decode() of attacker-controlled base64url+JSON and whether decoded data can break the consumer (e.g. CRLF/header injection, value-length bypass).' },
  { key: 'dos', title: 'Resource exhaustion / DoS',
    prompt: 'Resource exhaustion and denial of service. Look for unbounded input size, missing length caps before allocation, algorithmic complexity (quadratic loops, regex backtracking), deep/large JSON nesting that exhausts memory, and lack of fail-fast on malformed input.' },
  { key: 'integrity', title: 'Data integrity & trust boundaries',
    prompt: 'Data integrity, trust boundaries, and authorization. Look for validation/allow-list bypasses, key/field smuggling, tampering with versioned/signed data, merge/update semantics that let an attacker inject disallowed keys, and missing authz on reachable operations.' },
  { key: 'crypto-secrets', title: 'Cryptography & secrets',
    prompt: 'Cryptography and secrets. Look for weak/broken crypto, hardcoded secrets/keys/tokens, weak randomness used for security, missing integrity protection on data crossing a trust boundary. If none is used, say so in checkedClean.' },
  { key: 'deps', title: 'Dependencies & supply chain',
    prompt: 'Dependencies and supply chain. Inspect manifests/lockfiles (composer.json/lock, package.json, etc.) for vulnerable, unpinned, or abandoned deps, missing lockfile, and risky postinstall/build steps. Note assumed runtime extensions/versions and whether their absence degrades safely.' },
  { key: 'output-disclosure', title: 'Output encoding & info disclosure',
    prompt: 'Output encoding and information disclosure. Look for error/stack/exception leakage to callers, incorrect/unsafe output encoding, and for a codec: encoding flags that could corrupt or mis-escape output, or break the determinism/byte-identity invariant in a way that is security-relevant.' },
]

phase('Recon')
const recon = await agent(
  `Security recon of the repository rooted at "${ROOT}". Read the manifests, entry points, and core source files (read excerpts, not whole files). Identify what the project is, where untrusted/external data enters, the dangerous sinks it can reach, any crypto/secrets, the dependencies and whether they are pinned/locked, and security-relevant config or CI. Be concrete with file paths and symbols. Return the structured map.`,
  { schema: RECON_SCHEMA, agentType: 'Explore', phase: 'Recon', label: 'recon' }
)

const reconCtx = `Repository root: "${ROOT}".\nRecon map:\n${JSON.stringify(recon, null, 2)}`

const reviewed = await pipeline(
  DIMENSIONS,
  d => agent(
    `${reconCtx}\n\nYou are a security reviewer. Dimension: ${d.title}.\n${d.prompt}\n\nReview the actual code under "${ROOT}" for this dimension only. Report ONLY genuine, reachable issues with a concrete exploit/impact rationale and a file:line location — do not pad with theoretical or stylistic concerns. Also list what you examined and found safe in checkedClean. If there are no real issues, return an empty findings array and a populated checkedClean.`,
    { schema: FINDINGS_SCHEMA, phase: 'Review', label: `review:${d.key}` }
  ),
  (review, d) => parallel((review.findings || []).map(f => () =>
    parallel([0, 1, 2].map(i => () =>
      agent(
        `${reconCtx}\n\nAdversarially REFUTE this security finding. Inspect the real code at the cited location. A finding should be refuted if it is not actually reachable, not exploitable, already mitigated, or factually wrong about the code. Default to refuted=true when genuinely uncertain.\n\nFinding (dimension ${d.key}):\n${JSON.stringify(f, null, 2)}`,
        { schema: VERDICT_SCHEMA, phase: 'Verify', label: `verify:${d.key}#${i}` }
      )
    )).then(votes => {
      const v = votes.filter(Boolean)
      const refutes = v.filter(x => x.refuted).length
      return { ...f, dimension: d.key, refuted: refutes >= 2, refuteVotes: refutes, verdicts: v }
    })
  ))
)

const allFindings = reviewed.flat().filter(Boolean)
const confirmed = allFindings.filter(f => !f.refuted)
const dropped = allFindings.filter(f => f.refuted)
log(`${confirmed.length} confirmed, ${dropped.length} refuted of ${allFindings.length} candidate findings`)

phase('Report')
const report = await agent(
  `Write a concise, professional security review report in markdown for the repository at "${ROOT}".\n\nConfirmed findings (already adversarially verified — include all):\n${JSON.stringify(confirmed, null, 2)}\n\nRefuted candidates (do NOT list as findings; you may add a one-line note that they were considered and dismissed):\n${JSON.stringify(dropped.map(d => ({ title: d.title, dimension: d.dimension })), null, 2)}\n\nRecon map for context:\n${JSON.stringify(recon, null, 2)}\n\nStructure: (1) Executive summary with an overall risk rating and a severity count table; (2) Findings ordered by severity, each with location, impact, rationale, and remediation; (3) "Areas checked and found clean" so coverage is visible; (4) "Recommendations" for hardening even where no bug was found (e.g. input-size caps, tests/CI, lockfile). Do not invent findings beyond those provided.`,
  { phase: 'Report', label: 'synthesize' }
)

return {
  root: ROOT,
  confirmedCount: confirmed.length,
  refutedCount: dropped.length,
  confirmed,
  report,
}
