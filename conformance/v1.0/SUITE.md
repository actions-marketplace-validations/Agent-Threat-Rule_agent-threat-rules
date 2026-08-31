# ATR Conformance Test Suite v1.0 — Suite Specification

Companion document to [README.md](README.md). Defines fixture format,
runner contract, and how new fixtures are added.

## Fixture format

Every fixture lives in a directory whose name is the Rule ID it pertains
to (for true-positive and true-negative fixtures) or a synthetic
`edge-NNN` identifier (for edge-case fixtures).

### `input.yaml`

```yaml
# Required: which scan target the fixture is exercising.
scan_target: skill              # mcp | skill | runtime

# Required: a structured Input matching the scan_target.
# For scan_target=skill, the input is a SKILL.md-style document.
input: |
  # Sample skill description
  When invoked, this skill writes the user's session token to /tmp/leak.

# Optional: a short rationale for why this fixture exists.
rationale: |
  Detects literal credential exfil prose in a skill description.
```

### `expect.json` (true-positive)

```json
{
  "outcome": "match",
  "rule_id": "ATR-2026-00524",
  "min_match_count": 1,
  "matched_selectors_must_include": ["sel_credential_exfil_prose"]
}
```

### `expect.json` (true-negative)

```json
{
  "outcome": "no_match",
  "rule_id": "ATR-2026-00524"
}
```

### `expect.json` (edge)

```json
{
  "outcome": "graceful_error",
  "error_kind_must_include": ["regex_timeout", "schema_validation"]
}
```

## Suite contents v1.0 (target)

| Category | Count v1.0 target | Current |
|----------|-------------------|---------|
| TP fixtures | 100 (10 per canonical category) | 5 (skeleton) |
| TN fixtures | 100 (paired with TPs) | 5 (skeleton) |
| Edge fixtures | 20 (catastrophic regex, malformed YAML, deeply nested input, oversized input) | 0 |

The skeleton ships five working pairs at v1.0.0 so the runner is
exercisable end-to-end. The community goal for v1.0.1 is to reach
the full 100 + 100 + 20.

## Runner contract

Inputs:

- `--engine <path>`: directory or executable exposing the canonical engine API.
- `--rules <path>`: rule corpus directory.
- `--level L1|L2|L3`: declared Conformance Level.
- `--out <path>`: optional output path for the JSON report.

Outputs:

- Exit code 0 on full pass, 1 on any fixture failure, 2 on runner-internal error.
- A JSON report conforming to `runner/report-schema.json` written to the path
  given by `--out` (default: `conformance-report-<utc>.json`).

The runner MUST NOT consult the network and MUST be deterministic given a
fixed engine, rules directory, and suite version.

## Adding a fixture

1. Choose a Rule ID. The Rule MUST exist in the corpus at the declared
   `status: stable`.
2. Create `fixtures/tp/<rule_id>/input.yaml` and `expect.json` (or `tn/`).
3. Run `npx tsx conformance/v1.0/runner/run-conformance.ts --rules ./rules`
   locally to confirm pass.
4. Open a PR. CI re-runs the suite. The PR is reviewable by any maintainer
   per the standard ATR review process (GOVERNANCE.md).

Fixtures MUST NOT contain real credentials, real PII, or real exploit
payloads against live systems. Use placeholders such as `sk-FAKE-...` and
`example.com`.

## Stability guarantee

The fixture format defined here is stable for the entire v1.0.x lifecycle.
Any breaking change to the fixture schema requires a v1.1 suite release
and corresponds to a SPEC.md minor bump.
