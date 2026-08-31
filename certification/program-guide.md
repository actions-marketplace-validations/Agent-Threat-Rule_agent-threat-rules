# ATR-Certified™ Program Guide

> **STATUS: PROPOSED v1.0 — NOT YET RATIFIED. NO PRODUCT IS CURRENTLY
> ATR-CERTIFIED™.** The trust mark program described here is in proposal
> stage. The mark itself is unregistered. No third-party audit lab has
> been engaged. Until the program is formally launched, do NOT use
> "ATR-Certified™" in any product collateral, even with permission.
> See `STANDARDIZATION-STATUS.md` at repo root for full status.

**Version:** 1.0
**Status:** Draft for AEP-005 ratification at TSC seating — NOT RATIFIED
**License:** CC BY 4.0
**Companion documents (on ratification):** `audit-template.md`, `certified-products.md`

---

## Why this program exists

A specification + conformance corpus tells anyone "is this implementation correct?" A certification program tells anyone "is this product safe to deploy in my regulated environment?" The two are related but distinct:

- Conformance is **technical**: pass the corpus, get the technical claim.
- Certification is **operational**: pass the corpus + pass an independent audit + maintain attestation, get the trust mark suitable for procurement / regulatory binders.

Per `governance/CHARTER.md` § 9, ATR runs two certification tracks. This guide is the authoritative description of both.

---

## ATR-Certified™ Skill (free, community-issued)

A trust mark for a specific SKILL.md, MCP server, or agent skill artifact that passes the published ATR rule corpus at L1 baseline conformance with **zero critical findings** and **zero high-severity findings**.

### Who can issue it

The CI infrastructure running on github.com/Agent-Threat-Rule. No human approval. CI output is the authority.

### How to apply

1. Open an Issue in the canonical repo with label `cert-skill-application`.
2. Provide:
   - Skill / MCP server name + version
   - Public URL to the artifact (or a public-readable git commit hash for review)
   - Email for badge issuance notification
3. CI runs the L1 conformance scan on the published artifact.
4. If clean: badge issued, 90-day validity.
5. If findings: report posted, applicant fixes + re-applies.

### What the badge claims

- "This artifact at this version was scanned against the canonical ATR rule corpus on [date] and produced zero critical and zero high-severity findings."
- "Validity expires at [date+90 days] OR the next ATR release that materially affects relevant rule categories, whichever is earlier."
- Nothing about runtime behaviour, ongoing security, or product quality outside the rule corpus scope.

### Cost

**$0.** Free, indefinitely. No fee schedule, no commercial relationship required.

### Why free

Per `governance/CHARTER.md` § 9 and the predecessor `GOVERNANCE.md` v1.1:

> The ATR Numbering Authority does not charge for, influence, or gatekeep skill certification outcomes. The CI output is the authoritative source.

The model is Let's Encrypt + MITRE ATT&CK: free trust marks where the technical determination can be automated. Charging for this would undermine the technical neutrality.

---

## ATR-Certified™ Enterprise (paid third-party audit)

A trust mark for a specific product release line that has passed independent audit by an accredited audit lab per `audit-template.md`.

### Who can issue it

An accredited audit lab from the ATR-Certified™ Audit Network. Initial network targets:

- One Big 4 firm (KPMG, PwC, Deloitte, EY)
- One specialist firm (NCC Group, Trail of Bits, Bishop Fox, or equivalent)
- One regional audit firm per major sovereign region (Asia, EMEA, Americas)

Auditor accreditation is a TSC Tier 3 decision per `governance/CHARTER.md` § 4. Initial accreditation criteria:
- Demonstrated experience auditing security-detection products
- Published methodology (no black-box audits)
- Independent of any single product vendor (no conflict of interest with applicant)
- Located in a jurisdiction with operative trade-secret + audit confidentiality protection

### How to apply

1. Vendor contacts an accredited audit lab from the published network.
2. Audit lab and vendor execute the standard audit per `audit-template.md`.
3. On pass, audit lab issues a signed audit report.
4. Vendor submits the signed audit report + a fee to the TSC (fee schedule below).
5. TSC publishes the certification in `certification/certified-products.md`.
6. Badge granted for 12 months. Annual re-attestation required.

### What the badge claims

- "This product at this version, audited by [lab] on [date], passes the published L1 (+optionally L2, L3) ATR conformance and meets the operational criteria in `audit-template.md`."
- "Certification valid until [date+1 year]. Renewal requires re-audit."
- Operational criteria covered: deployment configuration, key management for evidence signing, support response time, vendor security incident-response process.
- Nothing about ATR's own opinion on the product's commercial merits — certification is a technical + operational fact, not a recommendation.

### Cost (to the certified vendor)

- **Audit lab fees**: charged by the lab to the vendor. Industry standard for similar audits is $30-80K per release line, varying by product complexity. The TSC does not receive any portion of audit lab fees.
- **TSC certification fee**: $5,000 per product release line per year. This funds the program operations (audit lab accreditation review, certified-products registry maintenance, badge artwork hosting, public Q&A on certifications).

Fee waiver available on application for:
- Open-source non-commercial implementations
- Sovereign-issued products operated by national CERTs
- Academic research products
- Civil-society / non-profit operators

Fee waiver decisions are made by the TSC Certification Working Group within 14 days.

### How the program is funded

- TSC certification fees go to Open Source Collective Inc. (fiscal sponsor) earmarked for the certification program.
- Funds support: program staff (when scale justifies), legal counsel for trademark enforcement, audit lab network management, public registry hosting, annual program review.
- Annual financial report published per OSC standard procedures.

The TSC, individual TSC members, and the founder DO NOT receive any portion of certification fees as personal compensation. This is per `governance/CHARTER.md` § 6.

---

## What the badges look like (post-Phase 4)

Both badges follow C2PA's Content Credentials model:
- Visible logo on product surfaces (web, slideware, packaging)
- Machine-verifiable signed manifest linking to the canonical registry
- Public verification URL (e.g., `https://certified.agentthreatrule.org/v/<badge-id>`)

Badge artwork and verification infrastructure are Phase 4 deliverables.

---

## Renewal + revocation

### Renewal

ATR-Certified™ Skill: re-scan via CI on application. Free.

ATR-Certified™ Enterprise: re-audit by an accredited lab. Lab fees per lab pricing. TSC fee $3,000 (renewal rate, vs $5,000 initial).

### Revocation

Cause for revocation:
- Discovered material defect that contradicts the audit conclusion
- Vendor misuse of the badge in violation of `legal/trademark-policy.md`
- Vendor failure to maintain operational criteria (e.g., support response time decay)
- Material change to the product not covered by the audit

Revocation procedure:
1. Audit lab or TSC member raises a revocation issue with evidence.
2. 30-day cure period with notice to vendor.
3. If uncured: TSC Tier 2 vote (simple majority of 5 of 9).
4. Revocation published in `certified-products.md` with reason and timeline.

---

## Audit lab accreditation

See `accreditation-procedure.md` (Phase 4 deliverable).

Initial accreditation requires:
- Standard application form
- 3-year audit-practice history
- Methodology document
- COI policy
- TSC Tier 3 vote per `governance/CHARTER.md` § 4

---

## Annual program review

The Certification Working Group reports to the TSC annually:
- Certifications issued (count, breakdown by tier)
- Revocations issued (count, reasons)
- Audit lab network status
- Financial report (income vs program expenses)
- Issues raised and resolution

Reports published at `certification/annual-reports/<year>.md`.

---

## What this program deliberately does NOT do

- Does NOT score commercial product quality. Certification is a binary (passes audit / does not).
- Does NOT replace conformance corpus testing. The audit verifies operational criteria; conformance verifies technical correctness.
- Does NOT bias toward any vendor. The TSC's hard 2-cap per company group (charter § 3.1) applies to the Certification Working Group as well.
- Does NOT create a "tiered" certification beyond skill / enterprise. Adding tiers requires Tier 3 AEP.

---

## References

- `governance/CHARTER.md` § 9 (program structure)
- `legal/trademark-policy.md` (ATR-Certified™ mark usage)
- `audit-template.md` (operational criteria — Phase 4 deliverable)
- `accreditation-procedure.md` (audit lab admission — Phase 4 deliverable)
- C2PA Conformance Program: https://c2pa.org/conformance/
- FIDO Certified Program: https://fidoalliance.org/certification/
