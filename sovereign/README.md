# ATR Sovereign Sub-Ranges

> **STATUS: BOOTSTRAP — PROPOSED v1.0 mechanism, first sub-range issued
> 2026-05-25.** This directory holds rules issued under sovereign
> sub-range identifiers per `governance/CHARTER.md` § 8.2. Sovereign
> rules are NOT loaded by the canonical engine (`src/`) today;
> integration is future work per `spec/atr-event-v1.0.md` (the
> proposed event format reserves `atr.sovereign_attestation`).

---

## What this directory is for

The canonical ATR rule corpus uses the identifier format `ATR-YYYY-NNNNN`
(e.g., `ATR-2026-00001`). National authorities and standards bodies may
issue rules under their own attestation using the sovereign sub-range
format `ATR-XX-YYYY-NNNNN` where `XX` is an ISO 3166-1 alpha-2 country
code (or other ISO 3166 designation).

See `governance/CHARTER.md` § 8 (Numbering Authority and sovereign ID
ranges) and `spec/atr-event-v1.0.md` (atr.sovereign_attestation field +
3-tier trust model) for the full mechanism specification.

---

## Directory layout

```
sovereign/
├── README.md          ← you are here
└── <XX>/              ← ISO 3166-1 alpha-2 country code
    ├── README.md      ← what authority issues this range and why
    ├── rules/         ← YAML rule files in ATR-XX-YYYY-NNNNN format
    └── attestation/   ← signed attestation files (Ed25519 signatures)
```

Currently populated:

- `TW/` — Taiwan sovereign sub-range, bootstrap issuance by maintainer
  (Adam Lin) pending formal Taiwan sovereign authority adoption

---

## Sovereign sub-range admission process (proposed)

A national authority or standards body wishing to issue rules under
`ATR-XX-YYYY-NNNNN`:

1. Opens an issue at github.com/Agent-Threat-Rule/agent-threat-rules
   tagged `sovereign-admission` with their `XX` request, signing
   authority identification, and public key for attestation.
2. Demonstrates either (a) governmental authority over `XX`
   (e.g., NIST for `US`, BSI for `DE`, NCA for `SA`) or
   (b) widely-recognized standing in `XX`'s AI security ecosystem
   (e.g., CIRCL for `LU`, CSIRT.CZ for `CZ`).
3. Commits to the conformance corpus signing requirement per
   `spec/conformance/SIGNING.md` if their rules will be included in
   conformance baselines.
4. TSC ratifies via Tier 3 vote per `governance/CHARTER.md` § 5.2.

Pre-TSC bootstrap: The maintainer (Adam Lin, Taiwan-citizen founder)
has issued the first sovereign sub-range (`TW`) as a demonstration of
the mechanism. This bootstrap issuance is **explicitly not** a claim
of Taiwan governmental authority. If or when a Taiwan sovereign body
(e.g., NAIO Malaysia equivalent for Taiwan, or 國家資通安全研究院)
adopts the ATR sovereign sub-range mechanism, the `TW` range
attestation MUST be re-issued under that authority's key, and the
maintainer's bootstrap attestation deprecated.

---

## Trust tier for sovereign rules (per spec/atr-event-v1.0.md)

When an engine fires a sovereign-prefixed rule, the emitted event
includes `atr.sovereign_attestation` containing signer + signature
chain. Downstream collectors apply differentiated trust policy:

- **Tier 1 (canonical):** TSC-merged `ATR-YYYY-NNNNN`. Full trust.
- **Tier 2 (sovereign-attested):** `ATR-XX-YYYY-NNNNN` with valid
  signature verifying against published sovereign key registry.
  Trust per collector's policy for sovereign `XX`.
- **Tier 3 (community / bootstrap / unverified sovereign):**
  Falls back to community-tier trust. Includes bootstrap-tier
  sovereign sub-ranges where the signing authority is a maintainer
  rather than a recognized sovereign body.

The `TW` range as currently issued falls under Tier 3 until a
formal Taiwan sovereign authority takes over.

---

## References

- `governance/CHARTER.md` § 8 — Numbering Authority and sovereign ID ranges
- `spec/atr-event-v1.0.md` § Sovereign attestation
- `spec/atr-event-v1.0.md` § 8 (security considerations on sovereign trust)
- `STANDARDIZATION-STATUS.md` — overall status of the proposal layer
