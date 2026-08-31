# Red Team Probe Proposals

This directory holds **draft ATR rule proposals** auto-generated from the
red-team probe submission pipeline.

## How a file lands here

1. A red-team researcher opens an issue using the
   [Red Team Probe Submission](https://github.com/Agent-Threat-Rule/agent-threat-rules/issues/new?template=red-team-probe.yml)
   template, with ≥3 positive examples and ≥3 negative (benign) examples.
2. `.github/workflows/red-team-probe-to-pr.yml` fires on the
   `red-team-probe` label, parses the issue body via
   `scripts/probe-to-atr.ts --issue-body`, writes the proposal to
   `proposals/red-team-probes/<slug>.proposal.yaml`, and opens a **draft PR**.
3. The submitter (or a maintainer) writes the detection regex on the PR
   branch. The PR's reviewer checklist tracks the remaining steps.

You can also run the converter locally:

```bash
git clone https://github.com/Agent-Threat-Rule/agent-threat-rules
cd agent-threat-rules
npm install
# Author your probe in a local YAML file (see schema below)
npx tsx scripts/probe-to-atr.ts --probe path/to/probe.yaml --write
```

The local mode produces the same on-disk file the workflow would, so you
can preview the output before submitting.

## Probe YAML schema (local mode)

```yaml
name: "Short title describing the attack family"
category: prompt-injection            # one of: prompt-injection,
                                      # agent-manipulation, tool-poisoning,
                                      # context-exfiltration,
                                      # credential-exfiltration,
                                      # model-abuse, privilege-escalation,
                                      # data-poisoning, supply-chain, other
severity: high                        # critical | high | medium | low
description: >
  Two or three sentences describing what the probe does and what
  capability the attacker abuses.
positive_examples:                    # ≥3 attack strings — become true_positives
  - "first attack payload"
  - "second attack payload"
  - "third attack payload"
negative_examples:                    # ≥3 benign lookalikes — become true_negatives
  - "first benign lookalike"
  - "second benign lookalike"
  - "third benign lookalike"
source_url: "https://arxiv.org/abs/..."   # optional
discovered_by: "Your Name (@yourhandle)"
cves:                                 # optional
  - "CVE-2026-XXXXX"
owasp_mapping:                        # optional
  - "LLM01:2025"
  - "AML.T0051"
notes: |                              # optional
  Anything that won't fit elsewhere.
```

## Lifecycle of a proposal

| Stage | Where the file lives | Status |
|---|---|---|
| Submitted | `proposals/red-team-probes/<slug>.proposal.yaml` | `status: draft`, `detection.conditions: []` |
| Regex drafted | same path, same PR branch | `detection.conditions: [...]` filled in |
| FP gate passed | same path | `check-rules-safety.ts` shows 0 FP on the 432-skill benign corpus |
| Promoted | `rules/<category>/ATR-2026-NNNNN-<slug>.yaml` | `status: experimental`, real ATR id assigned |
| Stable | same `rules/` path | `status: stable` after ≥30 days production observation, 0 FP reports |

## Why proposals live in their own directory

The engine in `src/engine.ts` only loads YAML files under `rules/`.
Anything in `proposals/` is invisible to consumers — exactly what you
want for half-finished detection logic. CI runs the schema validator
against proposals too, so a malformed proposal still fails fast, but
nobody is shipping a draft rule by accident.

## Promotion criteria

A maintainer should only move a file out of `proposals/red-team-probes/`
and into `rules/<category>/` when ALL of the following hold:

- [ ] `detection.conditions` is non-empty and matches every
      `test_cases.true_positives` entry.
- [ ] `detection.conditions` rejects every `test_cases.true_negatives`
      entry.
- [ ] `npx tsx scripts/check-rules-safety.ts <proposal path>` shows
      0 false positives on `data/skill-benchmark/benign/` (432 skills).
- [ ] The rule has the next free `ATR-2026-NNNNN` id assigned.
- [ ] `metadata_provenance.discovered_by` is preserved verbatim from the
      submission. The submitter is named in the `author` field (alongside
      `ATR Community`).
- [ ] CI (`validate.yml`, `rule-quality.yml`) passes on the PR.

The proposal file is deleted at the moment of promotion — the rule file
replaces it. The originating issue is closed by the promotion commit
via `Closes #N` in the message.
