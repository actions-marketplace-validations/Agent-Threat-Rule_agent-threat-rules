# Supporting Agent Threat Rules (ATR)

ATR is an MIT-licensed open detection rule standard for AI agent attacks. The rule corpus, detection engine, benchmark methodology, and integration tooling are maintained by a solo maintainer with community contributions. There is no commercial entity gating any part of the open standard.

If you depend on ATR in production or want the open standard to keep shipping, you can back the project through any of the following channels.

---

## 1. Manifund (US tax-deductible)

Manifund routes donations through Manifold for Charity, a registered 501(c)3 in Austin, Texas (EIN 88-3668801). Donations are US tax-deductible.

Project page:
https://manifund.org/projects/agent-threat-rules-atr-open-detection-rule-corpus-for-ai-agent-attacks

Minimum funding: 30,000 USD (6 months full-time maintenance)
Funding goal: 50,000 USD (adds external security audit + second-maintainer onboarding)
Closing: 2026-06-12

You can donate any amount. Donations route through Manifold for Charity 501(c)3.

---

## 2. Ko-fi (small donations, fast, no minimum)

Ko-fi accepts payments via PayPal and credit/debit card. Lower friction than Manifund for small one-off donations.

REPLACE_ME: https://ko-fi.com/agentthreatrules

Starting at 5 USD. No login required for donors.

---

## 3. Crypto (direct, no platform fees)

The same EVM wallet address receives funds on five chains: Ethereum mainnet, Base, Arbitrum, Optimism, and Polygon. Pick whichever chain has the lowest gas fee at the time of your donation.

Wallet address (all 5 EVM chains):

REPLACE_ME_WITH_0x_ADDRESS

QR code:

REPLACE_ME_WITH_QR_PATH

Recommended assets:
- ETH or USDC on Ethereum mainnet (best for donations over 500 USD where gas does not matter)
- USDC on Base (best for donations under 500 USD, gas typically under 0.10 USD)
- USDC on Arbitrum or Optimism (alternative low-gas L2)
- MATIC or USDC on Polygon (alternative low-gas chain)

ENS name (when registered):
REPLACE_ME.eth

---

## What your donation funds

50 USD funds reviewing one CISA KEV CVE entry and shipping a validated detection rule, complete with true-positive fixtures and a clean regression run against the 432-entry benign corpus. One extra rule the AI security ecosystem did not have before.

500 USD funds one week of full-time corpus expansion. The pipeline ingests CISA KEV and AVID feeds daily; human-in-the-loop validation is the rate-limiting step.

5,000 USD funds an independent security audit of the detection engine and rule parser, subcontracted to an external firm.

30,000 USD covers 6 months of full-time maintenance from a solo founder (Taiwan modest living rate).

50,000 USD covers the above plus the external audit plus onboarding a second maintainer to break the bus factor risk.

---

## Recognition

Every donor (regardless of amount) is listed in the CONTRIBUTORS file in the repository. Anonymity is the default option if you prefer not to be listed.

For donations above 1,000 USD, optional acknowledgment in the project README under "Sustaining Supporters." For donations above 10,000 USD, optional acknowledgment in release notes and conference-talk slides.

---

## Commitment

The ATR rule corpus, detection engine, and benchmark methodology are MIT licensed in perpetuity. No vendor-private exclusives. No paywall. No commercial fork that holds back rules from the open repository. Every PR is reviewed in the open.

The maintainer commits to:
- Publishing every benchmark with its underlying corpus, so any third party can reproduce.
- Documenting limitations honestly. The README maintains a public list of known evasion techniques (currently 64).
- Disclosing all financial sponsors in the CONTRIBUTORS file.
- Treating ATR as a community standard, not a proprietary product.

---

## Other ways to help (no money required)

- Star the repository on GitHub: helps surface ATR to other defenders
- Open issues with attack examples ATR misses: directly improves the rule corpus
- File integration PRs for new agent frameworks, MCP servers, or threat intelligence platforms
- Cite ATR in your security write-ups, blog posts, conference talks
- Try the npm package or GitHub Action in your CI/CD and report what works or breaks

Repository: https://github.com/Agent-Threat-Rule/agent-threat-rules
Public ecosystem map: https://sovereign-ai-defense.vercel.app

Maintainer: Adam Lin (adam@agentthreatrule.org)
