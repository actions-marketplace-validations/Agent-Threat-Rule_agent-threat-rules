# ATR Conformance Test Suite v1.0

This directory is the normative test suite referenced by [SPEC.md §12](../../SPEC.md).
Implementations that claim "ATR-Compatible L1/L2/L3" MUST pass it.

## Layout

```
conformance/v1.0/
  README.md           ← this file
  SUITE.md            ← suite specification (what each fixture asserts)
  fixtures/
    tp/               ← true-positive fixtures (rule MUST match)
      <rule_id>/
        input.yaml    ← attack payload
        expect.json   ← expected Match per SPEC §7
    tn/               ← true-negative fixtures (rule MUST NOT match)
      <rule_id>/
        input.yaml
        expect.json
    edge/             ← ambiguous inputs (engine MUST report error gracefully)
      <case_id>/
        input.yaml
        expect.json
  runner/
    run-conformance.ts  ← reference test runner
    report-schema.json  ← schema for runner output
  registry/
    README.md         ← list of verified ATR-Compatible implementations
```

## What the suite verifies

| Level | Requirement (SPEC §11) |
|-------|------------------------|
| L1    | Engine loads the published Corpus without parse errors and emits Match output per SPEC §7 for at least one Rule. |
| L2    | 100 % pass on TP fixtures **and** zero matches on TN fixtures for the declared Spec version. |
| L3    | L2 conformance plus output emission in two or more interchange formats (JSON + one of SARIF, STIX 2.1, MISP, OpenCTI) plus published FP rate against the public benign corpus. |

## Running the suite

```bash
# Against the in-tree reference engine
npm install
npm run build
npx tsx conformance/v1.0/runner/run-conformance.ts \
  --engine ./dist \
  --rules  ./rules \
  --level  L2

# Against a third-party engine that exposes the same CLI surface
npx tsx conformance/v1.0/runner/run-conformance.ts \
  --engine /path/to/your-engine \
  --rules  ./rules \
  --level  L2
```

The runner exits 0 on full pass, 1 on any failure. A machine-readable
report is written to `conformance-report-<utc-timestamp>.json` conforming
to `runner/report-schema.json`.

## Submitting a certification claim

After a passing run, file a `certification-claim` issue per
[TRADEMARK.md §5](../../TRADEMARK.md). The ATR Numbering Authority will
reproduce the run on a clean environment and, on success, add your engine
to `registry/` and authorize the ATR-Certified mark per the same policy.

## Versioning

This suite is `v1.0`. It tracks `SPEC.md v1.0.x`. Patch releases of the
suite (`v1.0.1`, `v1.0.2`...) MAY add fixtures and MUST NOT remove or
alter existing ones — a passing engine at `v1.0.0` MUST continue to pass
at `v1.0.x`. Minor releases (`v1.1`) align with `SPEC.md v1.1.x` and MAY
require new conformance behavior.

## License

The suite, including all fixtures, is published under the MIT License.
