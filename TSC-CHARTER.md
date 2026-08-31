<div align="center">

<img alt="ATR — Agent Threat Rules" src="assets/logo-light.png" width="320" />

# Technical Steering Committee Charter

[![Status](https://img.shields.io/badge/status-Draft-orange?style=flat-square)](#)
[![Effective](https://img.shields.io/badge/effective-TBD-lightgrey?style=flat-square)](#)
[![Authority](https://img.shields.io/badge/authority-BDFL_transitional-blue?style=flat-square)](docs/BDFL-charter.md)
[![Version](https://img.shields.io/badge/version-1.0.0-brightgreen?style=flat-square)](#10-revision-history)

</div>

---

## 1. Purpose

The Agent Threat Rules (ATR) project is an open detection rule standard
for AI agent security threats. This Charter establishes the Technical
Steering Committee (TSC), the multi-stakeholder body that succeeds the
transitional BDFL authority defined in [docs/BDFL-charter.md](docs/BDFL-charter.md)
and assumes ongoing technical decision authority over the project's
specification, rule corpus, and conformance program.

This Charter is normative for TSC operations. Where this Charter and
[GOVERNANCE.md](GOVERNANCE.md) disagree on procedural matters, this
Charter governs. Where this Charter and [SPEC.md](SPEC.md) disagree on
technical matters, SPEC.md governs.

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in BCP 14 when, and only
when, they appear in all capitals.

## 2. Authority and Scope

### 2.1 What the TSC Decides

The TSC has final decision authority over:

a. **Rule ID assignment** — confirming, blocking, or revoking
   `ATR-YYYY-NNNNN` identifiers in the official Corpus.
b. **Specification amendments** — additions, deprecations, and editorial
   changes to [SPEC.md](SPEC.md).
c. **Category structure** — admission, retirement, or renaming of the
   canonical categories enumerated in SPEC.md §8.
d. **Conformance program** — the Conformance Test Suite contents,
   verification process, and ATR-Compatible registry decisions.
e. **Enterprise Member admissions** — per [docs/BDFL-charter.md §Enterprise Member Program](docs/BDFL-charter.md#atr-enterprise-member-program----10000--year).
f. **Trademark policy** — per [TRADEMARK.md](TRADEMARK.md) Section 9.

### 2.2 What the TSC Does NOT Decide

The TSC MUST NOT take any of the following actions, even by unanimous
vote:

a. Change the project license from MIT to any other license
   ([docs/BDFL-charter.md](docs/BDFL-charter.md) §7).
b. Accept payment in exchange for rule acceptance, rejection, or
   ordering ([docs/BDFL-charter.md](docs/BDFL-charter.md) §3).
c. Adopt rules without the published quality gate and conformance
   review process (SPEC.md §11, §12).
d. Reassign or recycle previously-assigned Rule IDs (SPEC.md §4.2).

### 2.3 Reserved BDFL Authority (Transitional)

Until the TSC is fully seated and its initial cycle is complete, the
following authorities remain with the BDFL:

a. First convening of the TSC and acceptance of the inaugural seats.
b. Tie-breaking in the event of a deadlock during the Founding Three
   phase (see §3.1).
c. Public communication on behalf of the project pending TSC ratification
   of a Communications Lead.

These authorities transfer to the TSC upon the completion of the first
six (6) full meeting cycles.

## 3. Composition

### 3.1 Founding Three (v1.1, Target Q3 2026)

The TSC is constituted with three (3) seats, designed to break the
single-maintainer governance risk while remaining operationally light:

| Seat | Selection Basis |
|------|----------------|
| Maintainer Seat | Held by the BDFL of record at the time of TSC formation. |
| Industry Seat | An external maintainer at an organization that ships ATR rules in production at the time of nomination. |
| Community / Threat-Intel Seat | An external maintainer at a standards body, government CERT, or recognized open threat-intel project. |

Seat holders MUST be individuals, not organizations. An organization
MAY indirectly hold a seat by employing the seat-holder, but the seat
follows the person upon role change. The seat-holder MUST disclose any
employment change within 14 days of its effective date.

### 3.2 Expanded Composition (v1.2, Target Q1 2027)

The TSC expands to five (5) seats at the start of the v1.2 cycle by
adding:

- **Academic / Research Seat** — an independent AI security researcher.
- **Government / Standards-Body Seat** — a representative from CISA,
  NIST, ENISA, a national CERT, or an equivalent body.

The two original external seats (Industry, Community) retain their
holders. The Founding Three remain in office through the expansion.

### 3.3 No Concurrent Seats

A single individual MUST NOT hold more than one TSC seat
simultaneously, and MUST NOT hold a TSC seat while serving as an
Enterprise Member voting representative for the same organization.

## 4. Terms

### 4.1 Founding Three Terms

Seats are seated with staggered initial terms to enable continuity:

| Seat | Initial Term | Subsequent Terms |
|------|-------------|------------------|
| Maintainer Seat | 3 years | 2 years |
| Industry Seat | 2 years | 2 years |
| Community / Threat-Intel Seat | 3 years | 2 years |

Subsequent terms in §4.1 begin on completion of the initial term. A
seat-holder MAY stand for re-election with no term limit.

### 4.2 Expansion Seats

The Academic Seat and Government Seat introduced in v1.2 begin with
initial 2-year terms and follow 2-year terms thereafter.

### 4.3 Term Start and End

A term begins on the date the seat-holder is formally admitted by the
sitting TSC (or by the BDFL, for the Founding Three) and ends two or
three years later, as defined in §4.1, on the calendar anniversary of
admission unless the seat is vacated earlier under §8.

## 5. Decision-Making

### 5.1 Vote Thresholds

| Decision Class | Founding Three (3 seats) | Expanded TSC (5 seats) |
|---------------|--------------------------|-------------------------|
| Routine rule ID assignment | 2 of 3 majority | 3 of 5 majority |
| Spec amendments (§2.1.b) | 2 of 3 + 14-day public comment | 3 of 5 + 14-day public comment |
| Category structure (§2.1.c) | 2 of 3 + Spec PR | 3 of 5 + Spec PR |
| Enterprise Member admission | 2 of 3 | 3 of 5 |
| TSC seat replacement (§8.2) | 3 of 3 supermajority | 4 of 5 supermajority |
| Trademark policy amendment | 3 of 3 supermajority + 14-day comment | 4 of 5 supermajority + 14-day comment |
| Charter amendment | 3 of 3 supermajority + 21-day comment | 4 of 5 supermajority + 21-day comment |
| License change | NOT PERMITTED | NOT PERMITTED |

### 5.2 Public Comment Periods

Where a decision class requires a public comment period, the proposal
MUST be:

a. Posted as an Issue or Discussion on the canonical repository.
b. Open for the full comment period before the vote begins.
c. Linked from the relevant Spec section or Charter section it
   modifies, before the vote begins.

Substantive changes to a proposal during the comment period MUST
restart the comment clock.

### 5.3 Quorum and Recusal

A vote requires quorum of two-thirds of the seated TSC at minimum. A
seat that is vacant under §8 counts neither toward quorum nor toward
the threshold.

A TSC member MUST recuse from a vote under any of the conditions in
[docs/BDFL-charter.md §5](docs/BDFL-charter.md). A recused seat is
treated as vacant for that specific vote.

### 5.4 Voting Mechanism

Votes are conducted in one of two ways:

a. **Live vote** during a scheduled TSC meeting, recorded in the
   meeting minutes.
b. **Asynchronous vote** via a GitHub Issue tagged `tsc-vote`, open
   for at minimum 72 hours; the issue MUST link to the proposal
   document and clearly state the vote-close timestamp.

Either mechanism produces a binding decision. A live vote MUST be
recorded in minutes published per §6.4.

## 6. Meetings

### 6.1 Cadence

The TSC SHALL hold a regular public meeting every two weeks (bi-weekly).
The default duration is thirty (30) minutes. The TSC MAY adjust cadence
or duration by simple majority but MUST NOT meet less than once per
month.

### 6.2 Public Access

All regular TSC meetings are open to the public for observation. The
meeting link, time, and agenda MUST be published in the public ATR
Calendar at least 48 hours in advance.

The TSC MAY enter an executive session under §6.3.

### 6.3 Executive Session

The TSC MAY meet in executive session, with observers excluded, only
for one of the following purposes:

a. Discussion of a pending Enterprise Member admission where confidential
   commercial information has been shared.
b. Discussion of a pending conflict-of-interest determination.
c. Discussion of a pending personnel matter affecting a TSC seat-holder.

The minutes of an executive session MUST record the date, the purpose
category, the participants, and the decisions reached. Substantive
content of the discussion MAY be redacted; the existence of the session
and its decisions MUST NOT be.

### 6.4 Minutes

A nominated minute-taker MUST publish minutes to the canonical
repository under `meetings/YYYY-QN/YYYY-MM-DD.md` within seven (7) days
of the meeting. Minutes follow the template at
[meetings/TEMPLATE.md](meetings/TEMPLATE.md) (latest version).

Minutes MUST include:

a. Date, time, duration, location (URL).
b. Attendees, with affiliations, marked as present, observer, or apologies.
c. Each agenda item with discussion summary and decisions.
d. Vote tallies for each decision.
e. Action items with owners and due dates.
f. Date of next regular meeting.

## 7. Conflict of Interest

The Conflict of Interest policy in
[docs/BDFL-charter.md §5](docs/BDFL-charter.md) applies to all TSC
members in full. Specific TSC-applicable additions:

a. A TSC member MUST disclose any change to their primary employment
   within 14 days. The disclosure is recorded in the public
   `CONTRIBUTORS.md` and surfaced at the next meeting.
b. A TSC member MUST recuse from any vote whose outcome would directly
   benefit, financially or reputationally, an entity in which the
   member holds equity exceeding 1% of total outstanding shares or
   options.
c. The TSC MAY, by 2-of-3 (Founding) or 3-of-5 (Expanded) vote, require
   a member to recuse from a specific class of decisions for a defined
   period, where the member's accumulated disclosures present an
   ongoing conflict pattern.

## 8. Resignation, Replacement, and Removal

### 8.1 Resignation

A TSC member MAY resign at any time by written notice to the project
mailing list. The resignation is effective immediately upon receipt
unless the member specifies a later effective date.

### 8.2 Replacement

When a seat is vacated by resignation, end of term, or removal:

a. The TSC SHALL issue a public call for candidates within 14 days.
b. The call SHALL be open for at minimum 30 days.
c. The remaining seated TSC members SHALL select the replacement by
   supermajority vote per §5.1.
d. The replacement serves for the remainder of the vacated term, then
   stands for a regular term per §4.

### 8.3 Removal

A TSC member MAY be removed for cause by supermajority vote of the
remaining members. Cause is limited to:

a. Failure to attend three consecutive regular meetings without
   apology and without designating an alternate.
b. Violation of the Code of Conduct after a written warning.
c. Violation of the Conflict-of-Interest policy after a written
   warning.
d. Material misrepresentation of credentials, affiliation, or
   disclosure.

The member subject to a removal vote MUST be given written notice and
an opportunity to respond before the vote, and MUST recuse from the
vote itself.

### 8.4 Vacancy Floor

If the seated TSC falls below two members during the Founding Three
phase, or below three members during the Expanded phase, the BDFL
authority defined in §2.3 SHALL be reactivated for the duration of the
vacancy, regardless of whether the initial six-cycle threshold has
been met.

## 9. Amendment Process

This Charter is amended by:

a. A pull request against this file proposing the change.
b. A 21-day public comment period opened by an Issue tagged
   `charter-amendment`.
c. Approval by 3-of-3 supermajority (Founding) or 4-of-5 supermajority
   (Expanded).

Editorial corrections to spelling, grammar, broken links, or formatting
that do not change substantive policy MAY be merged by any TSC member
with a written rationale in the PR, without a comment period.

## 10. Effective Date and Revision History

This Charter is effective on the date the first complete TSC vote is
recorded under the procedures it defines.

| Version | Date | Editor | Summary |
|---------|------|--------|---------|
| 1.0.0 (Draft) | 2026-05-16 | Adam Lin (BDFL) | Initial Founding Three charter |

---

<div align="center">

[SPEC.md](SPEC.md) · [GOVERNANCE.md](GOVERNANCE.md) ·
[docs/BDFL-charter.md](docs/BDFL-charter.md) · [TRADEMARK.md](TRADEMARK.md)

</div>
