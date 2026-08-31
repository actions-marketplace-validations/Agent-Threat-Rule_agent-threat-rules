# ATR Telemetry Worker

Cloudflare Worker stub for the telemetry feedback endpoint described in
[docs/telemetry-spec.md](../../docs/telemetry-spec.md).

## What this is

A Cloudflare Worker that:

- Accepts `POST /v1/report` with the ATR telemetry schema.
- Validates HMAC-SHA256 signature against a per-consumer pre-shared key.
- Rejects requests that contain forbidden PII fields (user_id,
  session_id, ip_address, raw_event, etc.).
- Stores accepted reports in a Workers KV namespace, keyed
  `<consumer>/<YYYY-MM-DD>/<report_id>`.
- Returns 202 with an opaque `report_id` for the consumer's audit.

The daily aggregator (`scripts/aggregate-telemetry.ts` in the repo
root) reads from this KV out-of-band.

## What this is NOT (yet)

- Not deployed. The repo carries the source so the spec is implementable
  by anyone, and so the first downstream consumer can review the code
  before committing to integration.
- Not connected to live consumers. There's no HMAC key registered
  because no consumer has wired up yet.
- Not stateful beyond KV. No analytics, no log piping, no third-party
  sinks.

## Deployment, when the first consumer commits

```bash
cd infra/telemetry-worker
npm install -g wrangler
wrangler login

# Create the KV namespace and paste its id into wrangler.toml.
wrangler kv namespace create REPORTS

# Register per-consumer HMAC keys. The consumer is given the same key
# out-of-band over a secure channel.
wrangler secret put CONSUMER_KEY_microsoft_agt   # paste 32+ char random key
wrangler secret put CONSUMER_KEY_cisco_ai_defense
# … one per registered consumer

# Deploy.
wrangler deploy

# Health check.
curl https://atr-telemetry.<account>.workers.dev/v1/health
```

DNS will point `telemetry.agentthreatrule.org` at the Worker once the
first consumer is ready. Until then it lives on the default
`*.workers.dev` hostname for early integration testing.

## Local testing

```bash
cd infra/telemetry-worker
npm install
wrangler dev   # runs at http://localhost:8787

# In another shell, send a sample report:
node ../scripts/send-sample-report.js   # to be written when needed
```

## Cost

At expected scale (≤10 consumers × 1 report/hour each), the Worker
runs well inside Cloudflare's free tier. KV storage is ~5 KB per
report × 24 reports/day × 60-day TTL × 10 consumers = ~75 MB max,
also free.

## Security

- HMAC keys never leave Cloudflare's encrypted secret store. The
  Worker reads them at request time only.
- Consumer ids are validated against the allowlist (any
  `CONSUMER_KEY_<id>` secret existing). Unknown ids return 401 with
  no further detail.
- Rate limit: 1 report per consumer per hour, enforced via KV.
- Forbidden-field filter is intentionally conservative — adds friction
  for any consumer that accidentally pipes raw events. See
  `FORBIDDEN_FIELDS` in `src/index.ts`.

## What ATR can / cannot do with the data

The worker stores reports as-is. The aggregator (run as a GitHub
workflow against repo `data/telemetry/`, fed by a separate pull-from-KV
job) computes per-rule windowed statistics and writes them back into
the repo. Aggregates power `scripts/maturity-promote.ts` decisions.
No raw report data ever lives in the public repo.
