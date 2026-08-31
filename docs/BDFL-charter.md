# ATR Foundation — BDFL Charter

Version 1.0 · Effective 2026-04-22

---

## Preamble

The Agent Threat Rules (ATR) project operates as an open standard for AI agent security
detection. This document formalizes the project's leadership structure, governance
obligations, conflict-of-interest rules, and the two community programs that define
ATR's relationship with the broader security industry: the ATR Certified Skill program
and the ATR Enterprise Member program.

ATR is governed in the tradition of open-source projects that separate technical
authority from commercial relationship. Quality decisions are made by the community
and enforced by CI. Commercial relationships (Enterprise Membership) carry no
influence over detection quality or rule acceptance.

---

## Role of the BDFL

The BDFL (Benevolent Dictator For Life) is the transitional authority for the ATR project
during the period before the Technical Steering Committee (TSC) reaches operating
capacity. The BDFL holds final decision authority over:

- Rule ID assignment (ATR Numbering Authority)
- RFC amendments (schema, quality standard, governance)
- Tag membership admissions
- Category structure changes
- Enterprise Member admissions

The BDFL is not a commercial role. The BDFL does not approve or reject Enterprise
Members based on commercial considerations — membership is open to any organization
meeting the criteria in Section 6.

### Current BDFL

KUAN-HSIN LIN (林冠辛), GitHub: @eeee2345, email: adam@agentthreatrule.org

Designation: Transitional BDFL. This role exists until the TSC is constituted (see
Section 4). At that point, BDFL authority transfers to the TSC by supermajority vote.

---

## BDFL Authority and Limits

The BDFL may:
- Assign permanent ATR-YYYY-NNNNN IDs
- Approve, reject, or request changes to any rule PR
- Amend the quality standard RFC with public comment period (minimum 14 days)
- Invite organizations to TAG or Enterprise Membership

The BDFL may NOT:
- Change the MIT License to any other license (irrevocable — see Section 7)
- Accept payment in exchange for rule acceptance, rejection, or acceleration
- Merge rules proposed by an organization in which the BDFL has an undisclosed
  financial interest (see Section 5)
- Remove a rule without stating the technical reason publicly in the PR thread

---

## Technical Steering Committee (TSC) — Target: Q3 2026 (Founding Three)

The TSC replaces the single-maintainer authority model. The detailed
charter for the TSC, including voting thresholds, term length, public
meeting cadence, conflict-of-interest policy, and resignation /
replacement procedures, is in [`TSC-CHARTER.md`](../TSC-CHARTER.md). On
matters where this document and TSC-CHARTER.md disagree, the Charter
governs for the v1.1 (Founding Three) phase and onward.

### Initial composition (v1.1 Founding Three)

3 seats:
- Maintainer (BDFL, transitional)
- Industry (external maintainer at an organization shipping ATR in production)
- Community / Threat-Intel (external maintainer at a standards body or open threat-intel project)

### Expanded composition (v1.2, Target Q1 2027)

The TSC expands to 5 seats by adding:
- Academic / Research seat (independent AI security researcher)
- Government / standards-body seat (CISA, NIST, ENISA, or national CERT equivalent)

### TSC authority

Once constituted, the TSC takes over the authorities enumerated in
[`TSC-CHARTER.md §2.1`](../TSC-CHARTER.md#21-what-the-tsc-decides), with
voting thresholds per [`TSC-CHARTER.md §5.1`](../TSC-CHARTER.md#51-vote-thresholds).

### Founding criteria (supersedes the 2027 thresholds previously in this section)

The Founding Three TSC is seated when:
- A maintainer seat-holder accepts (BDFL by default)
- Both an industry seat-holder and a community / threat-intel seat-holder accept in writing
- The TSC-CHARTER.md is published and ratified by the seated TSC at its first meeting

The 500-rules / 3-orgs / 2-Enterprise-Member thresholds in the prior
draft are retained as soft guidance for the v1.2 expansion only.

---

## Conflict of Interest Policy

### BDFL recusal

The BDFL must recuse from reviewing any PR or RFC when:
- The PR was authored by an organization in which the BDFL holds equity, employment,
  or a commercial contract exceeding $10,000/year
- The rule's detection patterns would specifically advantage or disadvantage a product
  or service in which the BDFL has an undisclosed financial interest

When the BDFL recuses, a TAG member with no conflict serves as acting reviewer.
Recusal must be stated publicly in the PR thread.

### Reviewer conflict of interest

Any reviewer (TAG member or community reviewer) must recuse from a PR when:
- They authored the rule being reviewed
- The rule names or targets a product made by their employer
- They have a personal or financial relationship with the PR author that could bias
  their review

---

## ATR Certified Skill Program — Free, Community-Run

ATR Certified Skill is a community-managed designation indicating that an MCP skill
has been reviewed against the current ATR rule corpus and passes with zero critical
findings.

### Model

This program follows the MITRE ATT&CK / Let's Encrypt transparency model:
- Certification decisions are made by the community, not by a commercial entity
- The certification process is open, documented, and reproducible
- Any organization may audit the certification methodology
- Results are public

### Cost: Zero

There is no fee for ATR Certified Skill certification. There will never be a fee.
Skill certification is a community service, not a revenue stream.

### Process

1. The skill author submits a scan request via GitHub Issue with the skill artifact
2. A community reviewer (any contributor with 2+ merged PRs) runs `atr scan` against
   the skill and posts the full output to the issue thread
3. If zero critical/high findings: the maintainer applies the `atr-certified` label
   and the skill is added to the ATR Certified Skills registry
4. Certification is valid for 90 days or until a new ATR release that affects the
   relevant rule categories, whichever comes first

### Authority

The BDFL and TSC do not override community reviewer decisions on certification.
The CI output is the authoritative source. If `atr scan` returns zero critical
findings against the latest ATR release, the skill is certified. No exceptions.

---

## ATR Enterprise Member Program — $10,000 / year

Enterprise Membership is modeled on the Apache Software Foundation Platinum Sponsor
model. It is a governance relationship, not a commercial license. The MIT License
grants all commercial rights to everyone at zero cost.

### What Enterprise Membership is

- Formal recognition as a supporter of the ATR standards project
- Governance participation rights (see below)
- Access benefits for enterprise security teams

### What Enterprise Membership is NOT

- Not a commercial license (MIT License is free for all uses)
- Not influence over rule acceptance or rejection decisions
- Not priority treatment in the numbering queue
- Not a certification or endorsement of any product

### Benefits

| Benefit | Detail |
|---------|--------|
| Governance vote | One vote per organization in TSC-level decisions after TSC formation |
| Early draft access | New RFC drafts shared 14 days before public comment period opens |
| Priority PR review | PRs from Enterprise Members tagged `priority-review` are reviewed within 7 days (vs 14-day standard SLA) |
| Logo display | Organization logo in ATR repository README and website under "Enterprise Members" |
| Direct contact | Access to a private mailing list for coordinating vendor-pack rule contributions |

### Eligibility

Any organization may apply, subject to:
- Demonstrated use of ATR in a security product, research project, or internal tooling
- Willingness to have the membership publicly listed (no anonymous members)
- Payment of the annual $10,000 fee to the ATR Foundation treasury

### Limitations on Enterprise Member influence

Enterprise Member status grants governance voting rights on structural decisions
(RFC amendments, TSC composition, roadmap priorities). It does NOT grant:
- Any vote on individual rule acceptance or rejection
- Any ability to accelerate or block specific rule IDs
- Any access to non-public scan data from other organizations' Threat Cloud sensors

Decisions about individual rule quality are made solely by the quality gate CI and
human reviewers following the standard review process in REVIEWER-GUIDE.md.

### Current fee: $10,000 / year

This fee supports project infrastructure (CI, npm hosting, Zenodo DOI, website). The
annual accounts are published publicly each December. If the TSC determines the fee
creates a barrier to adoption by important community organizations, it may create a
scholarship track for non-commercial and academic members.

---

## License Commitment — Irrevocable

ATR is licensed under the MIT License. This is irrevocable. The BDFL, TSC, and
Enterprise Members collectively cannot change the license to any source-available,
commercial, or proprietary license.

This is not a policy — it is a structural commitment. ATR's value as a community
standard depends on the unconditional trust that any organization — Cisco, Microsoft,
NVIDIA, a university research lab, an individual developer — can use, embed, and
build upon ATR rules without legal risk, forever. A standards body that can revoke
free use is not a standards body.

If a future TSC majority attempts a license change, any community member may fork the
repository under the MIT License using any version of the corpus prior to the attempted
change. The numbering authority would shift to the fork.

---

## Amendment Process

Amendments to this charter require:
- A PR against this file with the proposed change
- A 21-day public comment period (opened by issue tagged `charter-amendment`)
- BDFL approval (pre-TSC) or TSC supermajority 4/5 vote (post-TSC)

Minor editorial corrections (typos, grammar, formatting) may be merged by the BDFL
without a comment period, provided no substantive policy content changes.
