# Taiwan Sovereign Bootstrap Signing Guide

> **Audience:** Adam Lin (maintainer, bootstrap signing authority).
>
> **Purpose:** Step-by-step procedure to generate the Ed25519 signing
> key for `atr-tw-bootstrap-2026-05-25`, sign
> `sovereign/TW/attestation/2026-05-25-bootstrap.json`, publish the
> public key, and update the rule file with the signature.
>
> **Time required:** 20-30 minutes.

---

## Why this needs to be the maintainer, not Claude

The Ed25519 **private key** that signs the attestation MUST live with
Adam (the sovereign signing authority for this bootstrap range), not
with an AI agent. The agent can write the structure, document the
procedure, and verify the result — but the act of holding and using
the private key is the maintainer's job.

This separation is the entire point of the sovereign attestation
mechanism: an external verifier should be able to trust that the
signature was produced by the named human (or institution), not by
any party that had read access to the repo.

---

## Step 1: Generate the Ed25519 keypair

On a machine you trust (your laptop, not a shared CI runner):

```bash
# Generate the keypair
ssh-keygen -t ed25519 -f ~/.ssh/atr-tw-bootstrap-2026-05-25 -C "atr-tw-bootstrap@agentthreatrule.org" -N ""

# This produces:
#   ~/.ssh/atr-tw-bootstrap-2026-05-25       (private key — NEVER commit)
#   ~/.ssh/atr-tw-bootstrap-2026-05-25.pub   (public key)
```

Store the private key per your normal practice (1Password,
hardware token, encrypted backup). Add the private key path to
your shell environment so signing tools can find it:

```bash
echo 'export ATR_TW_SIGNING_KEY=~/.ssh/atr-tw-bootstrap-2026-05-25' >> ~/.zshrc
```

---

## Step 2: Get the public key in the format the attestation needs

The attestation file expects PEM-encoded Ed25519 public key. Convert:

```bash
# Extract raw public key bytes from OpenSSH format
ssh-keygen -e -m PKCS8 -f ~/.ssh/atr-tw-bootstrap-2026-05-25.pub > ~/atr-tw-bootstrap-2026-05-25.pub.pem

# View the PEM
cat ~/atr-tw-bootstrap-2026-05-25.pub.pem
# Should look like:
# -----BEGIN PUBLIC KEY-----
# MCowBQYDK2VwAyEAxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
# -----END PUBLIC KEY-----

# Compute SHA-256 fingerprint
openssl dgst -sha256 ~/atr-tw-bootstrap-2026-05-25.pub.pem | awk '{print $2}'
```

---

## Step 3: Publish the public key to the repo

```bash
cd ~/Downloads/agent-threat-rules
cp ~/atr-tw-bootstrap-2026-05-25.pub.pem sovereign/TW/attestation/2026-05-25-bootstrap-key.pub

# Update attestation file with the actual values
# (use your editor; replace PENDING_GENERATION placeholders)
$EDITOR sovereign/TW/attestation/2026-05-25-bootstrap.json
#   signing_key.public_key_pem: paste the PEM contents
#   signing_key.public_key_fingerprint_sha256: paste the SHA-256
```

---

## Step 4: Compute the rule content hash

```bash
# Canonical-form the rule file (strip trailing whitespace, normalize
# line endings, then hash)
sed 's/[[:space:]]*$//' sovereign/TW/rules/ATR-TW-2026-00001-taiwan-national-id-leak.yaml \
  | openssl dgst -sha256 \
  | awk '{print $2}'
```

Paste this hash into
`sovereign/TW/attestation/2026-05-25-bootstrap.json` →
`rules_covered[0].content_hash_sha256`.

---

## Step 5: Sign the attestation

The canonical form to sign is RFC 8785 JCS (JSON Canonicalization
Scheme) over the subset `{issued_at, scope, rules_covered[*].rule_id,
rules_covered[*].content_hash_sha256}`.

A minimal Python signing script (no external dependencies beyond
PyNaCl):

```bash
pip install pynacl pyjcs

cat > /tmp/sign-atr-tw.py << 'EOF'
import json
import sys
from pathlib import Path
from nacl.signing import SigningKey
from nacl.encoding import RawEncoder, Base64Encoder

# Load attestation
attestation_path = Path("sovereign/TW/attestation/2026-05-25-bootstrap.json")
attestation = json.loads(attestation_path.read_text())

# Build the canonical subset
subset = {
    "issued_at": attestation["issued_at"],
    "scope": attestation["scope"],
    "rules_covered": [
        {"rule_id": r["rule_id"], "content_hash_sha256": r["content_hash_sha256"]}
        for r in attestation["rules_covered"]
    ],
}

# Canonicalize (RFC 8785 JCS — simplified: sorted keys, no whitespace)
canonical = json.dumps(subset, sort_keys=True, separators=(",", ":")).encode("utf-8")

# Load private key from OpenSSH format (convert to raw Ed25519)
import subprocess
pem = subprocess.run(
    ["ssh-keygen", "-e", "-m", "PEM", "-f",
     str(Path.home() / ".ssh" / "atr-tw-bootstrap-2026-05-25")],
    capture_output=True, text=True, check=True
).stdout

# Use cryptography library to extract raw key bytes
from cryptography.hazmat.primitives.serialization import load_pem_private_key
private_key_obj = load_pem_private_key(pem.encode(), password=None)
raw_private = private_key_obj.private_bytes_raw()

# Sign
signing_key = SigningKey(raw_private)
signature = signing_key.sign(canonical, encoder=Base64Encoder).signature.decode("ascii")

# Print
print("Canonical form length:", len(canonical))
print("Signature (base64):", signature)
EOF

python3 /tmp/sign-atr-tw.py
```

Paste the base64 signature into
`sovereign/TW/attestation/2026-05-25-bootstrap.json` →
`rules_covered[0].signature` AND `signature_envelope.signature_base64`.

Also paste the signature into the rule file YAML →
`sovereign_attestation.signature` field (replacing
`PENDING_SIGNATURE_AWAITING_MAINTAINER_KEY_GENERATION`).

---

## Step 6: Verify

```bash
# Verify with the public key (round-trip sanity)
python3 -c "
import json
from pathlib import Path
from nacl.signing import VerifyKey
from nacl.encoding import Base64Encoder
from cryptography.hazmat.primitives.serialization import load_pem_public_key

# Load public key
pem = Path('sovereign/TW/attestation/2026-05-25-bootstrap-key.pub').read_bytes()
public_key_obj = load_pem_public_key(pem)
raw_public = public_key_obj.public_bytes_raw()
verify_key = VerifyKey(raw_public)

# Re-build canonical form
att = json.loads(Path('sovereign/TW/attestation/2026-05-25-bootstrap.json').read_text())
subset = {
    'issued_at': att['issued_at'],
    'scope': att['scope'],
    'rules_covered': [
        {'rule_id': r['rule_id'], 'content_hash_sha256': r['content_hash_sha256']}
        for r in att['rules_covered']
    ],
}
canonical = json.dumps(subset, sort_keys=True, separators=(',', ':')).encode('utf-8')

# Verify
signature_b64 = att['signature_envelope']['signature_base64'].encode('ascii')
verify_key.verify(canonical, signature_b64, encoder=Base64Encoder)
print('Signature verified.')
"
```

---

## Step 7: Commit + push

```bash
cd ~/Downloads/agent-threat-rules
git add sovereign/TW/
git commit -m "sovereign(TW): generate bootstrap signing key and sign ATR-TW-2026-00001

- Generated Ed25519 keypair (key_id: atr-tw-bootstrap-2026-05-25)
- Published public key + SHA-256 fingerprint
- Signed attestation file over canonical subset (issued_at + scope +
  rules_covered with content hashes)
- Updated rule file with signature

Trust tier: Tier 3 (bootstrap / unverified-sovereign) until formal
Taiwan sovereign authority adopts the ATR-TW range and re-attests.
Sunset: 2029-05-25 or earlier on re-attestation."

git push origin main
```

---

## After signing — what changes

- `sovereign/TW/attestation/2026-05-25-bootstrap.json`:
  - `signing_key.public_key_pem` populated
  - `signing_key.public_key_fingerprint_sha256` populated
  - `rules_covered[0].content_hash_sha256` populated
  - `rules_covered[0].signature` populated
  - `signature_envelope.signature_base64` populated
  - `_meta.status` updated to "ACTIVE — bootstrap signed and published"

- `sovereign/TW/attestation/2026-05-25-bootstrap-key.pub`: new file with PEM-encoded public key

- `sovereign/TW/rules/ATR-TW-2026-00001-taiwan-national-id-leak.yaml`:
  - `sovereign_attestation.signature` populated

---

## What happens if you don't sign

The rule file and attestation structure are in the repo and visible.
External readers can see the proposed sovereign mechanism and the
intent. But Tier 3 trust applies — no engine will treat ATR-TW-2026-00001
as sovereign-verified.

For the proposal stage, unsigned-but-structured is acceptable. For
credibility with OASIS / NIST / national authorities reviewing the
mechanism, signed-and-verified is significantly stronger.

Recommendation: sign before 2026-06-01 so the first ecosystem
notification email batch can cite a fully-signed example.

---

## Security notes

- Generate the keypair on a machine you trust. Never on a shared CI
  runner.
- The private key is sensitive. Treat it like an SSH key for a
  production server.
- If the private key is compromised, publish a revocation entry to
  `sovereign/TW/attestation/revocation-list.json` and re-issue under
  a new key ID.
- The 36-month sunset is intentional. Even uncompromised, keys should
  rotate. Schedule a calendar reminder for 2027-11-25 (18 months out)
  to plan re-attestation.

---

## Future: when Taiwan sovereign authority adopts

If 國家資通安全研究院 or 數位發展部 or equivalent adopts the ATR-TW
range, the process is:

1. They generate their own Ed25519 keypair under their institutional
   security regime.
2. They issue a new attestation file (`sovereign/TW/attestation/
   <date>-<authority>.json`) listing the rules they re-attest under
   their authority.
3. They open a PR adding their attestation and updating
   `sovereign/TW/README.md` to reflect the change in signing
   authority.
4. The bootstrap attestation
   (`2026-05-25-bootstrap.json`) is updated with
   `_meta.superseded_by` pointing to the new attestation.
5. The bootstrap key may be rotated out of the registry or kept as
   a co-signature path (defensive).

This is the path from "founder demonstration" to "Taiwan sovereign
authority recognized," which is the goal of issuing this range in
the first place.
