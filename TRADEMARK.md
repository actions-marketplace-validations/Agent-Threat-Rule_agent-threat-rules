<div align="center">

<img alt="ATR — Agent Threat Rules" src="assets/logo-light.png" width="320" />

# ATR Trademark and Brand Usage Policy

[![Status](https://img.shields.io/badge/status-Active-brightgreen?style=flat-square)](#)
[![Effective](https://img.shields.io/badge/effective-2026--05--16-lightgrey?style=flat-square)](#)
[![Authority](https://img.shields.io/badge/authority-BDFL_transitional-blue?style=flat-square)](docs/BDFL-charter.md)
[![Version](https://img.shields.io/badge/version-1.0.0-brightgreen?style=flat-square)](#)

</div>

---

## 1. Scope

This policy governs use of the project's word marks, logos, and certification
designations, collectively the "Marks":

| Mark | Form | Use |
|------|------|-----|
| `ATR` | Word mark | The project name and standard name |
| `Agent Threat Rules` | Word mark | The unabbreviated project name |
| `ATR-Certified` | Certification mark | Indicates a product or implementation has passed the Conformance Test Suite at a declared level |
| `Powered by ATR` | Attribution mark | Indicates a product incorporates ATR rules or engine but makes no conformance claim |
| ATR shield logo | Figurative mark | The graphical identifier of the project |

The Marks are pending registration with the United States Patent and Trademark
Office (USPTO). Prior to formal registration, this policy is enforced as a
community norm of the ATR project under common-law usage doctrine.

## 2. The Rule and the Marks Are Different Things

The rule corpus, schema, conformance test suite, and engine code are
licensed under the MIT License. Anyone may copy, modify, redistribute, or
embed them, including in commercial products.

The Marks are not licensed under MIT. Use of the Marks is governed by this
policy. This separation mirrors the practice of Linux Foundation projects
(the Linux kernel is GPL; the "Linux" mark is licensed by the Linux Mark
Institute) and MITRE ATT&CK (the framework content is open; product naming
is restricted).

## 3. Permitted Uses Without a License

The following uses are permitted without notice or fee, provided the use
is accurate and not misleading:

a. Referring to ATR by name in articles, blog posts, talks, books, research
   papers, regulatory documents, and similar editorial content.

b. Stating that a product or implementation "uses ATR rules," "implements
   ATR detections," or "consumes ATR YAML" when this is factually true.

c. Displaying the "Powered by ATR" attribution badge in product UI,
   marketing pages, README files, and similar contexts, provided:
   - The badge is rendered in its unmodified official form
   - The use does not imply endorsement or certification beyond what the
     project has formally granted
   - The badge links to https://agentthreatrule.org

d. Reproducing the official logo in articles, presentations, and similar
   editorial contexts where the use is descriptive and not promotional of
   the user's own goods or services.

## 4. Uses Requiring a License

The following uses require an explicit license from the ATR Numbering
Authority (currently the BDFL; transitions to the Technical Steering
Committee per GOVERNANCE.md):

a. Using "ATR" or "Agent Threat Rules" in a product name, service name,
   company name, or domain name (for example: ATR Pro, ATR Cloud, ATR
   Auditor, atr-scanner.com).

b. Using "ATR-Certified" or any visually similar phrase to describe a
   product, implementation, or audit outcome.

c. Selling merchandise (apparel, stickers, hardware) bearing the Marks.

d. Sponsoring events under a name that incorporates the Marks.

Unauthorized commercial use of the Marks is a violation of this policy and
may, after formal USPTO registration, also be a violation of trademark law.

## 5. The ATR-Certified™ Program

`ATR-Certified` is a certification mark. It indicates that an engine, scanner,
service, or implementation has passed the Conformance Test Suite published
in `conformance/` for the declared Spec version, at a declared Conformance
Level (L1, L2, or L3 per SPEC §11).

### 5.1 Eligibility

Any organization may apply for the right to display the `ATR-Certified` mark
on a specific product or implementation by:

1. Running the published Conformance Test Suite against the implementation.
2. Producing a reproducible test report with the suite version, the engine
   version, the date, and the achieved Conformance Level.
3. Filing the report with the ATR Numbering Authority via a public GitHub
   issue tagged `certification-claim`.

### 5.2 Verification

The ATR Numbering Authority reproduces the test report on a clean
environment. On a successful reproduction, the implementation is added to
the public registry at `conformance/registry/` and the organization is
authorized to display `ATR-Certified L<level>` for the verified product.

### 5.3 Term and Renewal

Certification is valid for 365 days or until a new SPEC.md major version is
published, whichever comes first. Renewal requires re-running the suite
against the latest published version.

### 5.4 Fees

For Spec v1.0.x and the v1.0 Conformance Suite, certification verification
is offered at no fee. After Spec v2.0 publication, the Technical Steering
Committee may introduce a verification fee of up to USD 1,000 per
implementation per year. The MIT-licensed rule corpus, schema, and
conformance fixtures will remain free regardless of any verification fee.

## 6. The "Powered by ATR" Attribution Badge

The "Powered by ATR" badge is an attribution mark, not a certification.

### 6.1 Use is free and unrestricted

Any product or implementation that incorporates one or more ATR rules, the
ATR schema, or the ATR engine MAY display the "Powered by ATR" badge at no
fee, without registration, and without prior approval. Display does not
imply that the project, the BDFL, the Technical Steering Committee, or any
maintainer endorses the product.

### 6.2 Conditions of use

a. The badge MUST link to https://agentthreatrule.org or
   https://github.com/Agent-Threat-Rule/agent-threat-rules.

b. The badge MUST NOT be modified beyond resizing or recoloring to a
   neutral grayscale variant. The official badge asset directory
   (`assets/badges/`) is forthcoming alongside the v1.0 conformance
   registry; until then, the project logo from `assets/logo-light.png`
   is the only authorized graphical asset.

c. The badge MUST NOT be used in a way that implies certification, an
   exclusive relationship, or endorsement.

## 7. Forks

A fork of the ATR repository MAY retain the Marks within unmodified files
copied from the upstream project (for example, leaving "ATR" in
`SPEC.md`, `README.md`, or rule YAML files). A fork MUST NOT:

a. Use "ATR" or "Agent Threat Rules" in the fork's repository name, npm
   package name, PyPI package name, or domain in a way that suggests
   official status (for example, `atr-official-fork`, `atr-pro-fork`).

b. Assign new identifiers in the `ATR-YYYY-NNNNN` namespace (see SPEC §4.3).

c. Display the "ATR-Certified" mark for the forked engine unless the fork
   has passed the Conformance Test Suite under its own name.

## 8. Reporting Misuse

To report misuse of the Marks, open a GitHub issue tagged `trademark-misuse`
or email trademark@agentthreatrule.org with:

- The product, service, or content allegedly misusing the Mark
- The URL or screenshot of the misuse
- Your contact information (optional but useful for follow-up)

The ATR Numbering Authority will:

1. Acknowledge receipt within 14 days
2. Contact the alleged misuser with a notice describing the policy
3. Track resolution publicly in the issue thread

## 9. Amendment

This policy may be amended by:

- A pull request against this file
- A 14-day public comment period (opened by an issue tagged
  `trademark-amendment`)
- BDFL approval (pre-TSC) or TSC supermajority as defined in
  GOVERNANCE.md (3-of-3 during the Founding Three phase; 4-of-5 after the
  v1.2 expansion)

Editorial corrections to spelling, grammar, broken links, and similar
non-substantive changes may be merged by the BDFL without a comment period.

## 10. Relationship to Other Policies

| Subject | Governing document |
|---------|--------------------|
| Rule corpus and engine code license | LICENSE (MIT) |
| Rule ID assignment | GOVERNANCE.md, SPEC.md §4 |
| Technical Steering Committee | GOVERNANCE.md, docs/BDFL-charter.md |
| Enterprise Member program | docs/BDFL-charter.md |
| Vulnerabilities in this policy or its enforcement | SECURITY.md |

## 11. Contact

- Trademark inquiries: trademark@agentthreatrule.org
- BDFL: adam@agentthreatrule.org
- General: https://github.com/Agent-Threat-Rule/agent-threat-rules

USPTO registration applications for the Marks named in Section 1 are in
preparation. This document will be updated to reflect application serial
numbers and registration status as filings progress.
