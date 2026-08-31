# Research-Mention Corpus

Samples of text that **mentions** an AI / agent / LLM attack but **is not**
an attack. These are the highest-FP-risk category — they're written
exactly the way attacks are written, except the surrounding context
makes them benign.

Every ATR rule's regex is validated against this corpus before merge:
**0 matches required**. If a rule fires on any of these, it gets the
`needs-human-review` label and stays out of `rules/`.

## Why this corpus exists

The single most common FP failure mode for ATR-style detection rules:

1. A researcher publishes a paper describing the **DAN jailbreak**.
2. The paper's abstract contains the phrase "the DAN jailbreak forces
   the model to ignore its safety guidelines."
3. An ATR rule for DAN detection naïvely matches that phrase.
4. Now every academic citation, security blog post, training course
   module, and CVE advisory triggers a false positive at Microsoft AGT /
   Cisco / wherever ATR consumers ship.

Sigma solved this for the SOC world by curating large benign-but-
attacker-keyword corpuses. ATR needs the AI/agent-specific equivalent.

## Source categories

Each sample in `corpus.jsonl` is one JSON line with `{ text, category,
source_type }`. Categories cover the main attack families ATR detects.
`source_type` is one of:

- `academic` — paper abstract, conference talk synopsis, arxiv title
- `security_blog` — vendor security blog post, write-up
- `readme` — security tool README explaining what it does
- `cve_text` — CVE / GHSA / advisory short description
- `news` — news article about an AI security incident
- `course` — training material / course module description
- `documentation` — official framework docs explaining a defence

## How to add samples

Open a PR adding lines to `corpus.jsonl`. Rules:

1. The text must clearly DESCRIBE an attack, not BE an attack.
2. Provide attribution via `source_url` field when possible.
3. Aim for diversity across attack families and source types.
4. Avoid synthetic / fabricated samples — pull from real published
   content with attribution.
5. Trim each sample to 1-3 sentences; longer texts dilute the FP
   signal.

The corpus is intentionally smaller than the benign-skill corpus (10K
words vs 50K) because each sample here is high-FP-risk by design.
Maintain quality over quantity.

## Cross-references

- `scripts/check-rules-safety.ts` — gate that consumes this corpus
- `docs/QUALITY-GATE.md` — full quality policy
- `data/skill-benchmark/benign/` — broader 432-skill benign corpus
  (different threat model: skills that look helpful but might have
  hidden malice)
