#!/usr/bin/env npx tsx
/**
 * aggregate-telemetry.ts
 *
 * Reads downstream-consumer telemetry reports from
 * data/telemetry/reports/<consumer>/<YYYY-MM-DD>.json (synced
 * out-of-band from the Cloudflare Worker's KV namespace — see
 * infra/telemetry-worker/) and computes the rolling 30-day per-rule
 * statistics that drive auto-promotion / auto-demotion decisions in
 * scripts/maturity-promote.ts.
 *
 * Output: data/telemetry/aggregate.json with the shape:
 *
 * {
 *   "computed_at": "2026-05-12T07:00:00.000Z",
 *   "window_days": 30,
 *   "rules": {
 *     "ATR-2026-00440": {
 *       "total_fires_30d": 8421,
 *       "fp_dismissed_30d": 12,
 *       "fp_confirmed_30d": 0,
 *       "fp_rate_30d": 0.00142,
 *       "consumer_count_30d": 3,
 *       "deployment_count_30d": 4271,
 *       "consumers": ["microsoft-agt", "cisco-ai-defense", "misp"],
 *       "first_seen": "2026-04-15T...",
 *       "last_seen": "2026-05-12T..."
 *     },
 *     ...
 *   },
 *   "consumers": {
 *     "microsoft-agt": { "reports": 28, "rules_reporting": 142, ... }
 *   }
 * }
 *
 * Per docs/telemetry-spec.md, the aggregator never preserves raw
 * report bodies in the public repo — only this digested file lands
 * in data/telemetry/aggregate.json. Raw reports stay in the KV
 * namespace (60-day TTL) and on whatever private storage the
 * downstream sync pipeline uses.
 *
 * Usage:
 *   npx tsx scripts/aggregate-telemetry.ts                # dry-run
 *   npx tsx scripts/aggregate-telemetry.ts --write        # write aggregate.json
 *   npx tsx scripts/aggregate-telemetry.ts --window 30    # window length in days
 *
 * Exit codes:
 *   0 success (even if no reports — emits empty aggregate)
 *   1 fatal (could not read reports dir)
 */

import {
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { dirname, resolve, join } from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const REPO_ROOT = resolve(__dirname, "..");
const REPORTS_DIR = resolve(REPO_ROOT, "data/telemetry/reports");
const OUT_FILE = resolve(REPO_ROOT, "data/telemetry/aggregate.json");

const args = process.argv.slice(2);
const flag = (n: string) => args.includes(n);
const opt = (n: string): string | undefined => {
  const i = args.indexOf(n);
  return i >= 0 ? args[i + 1] : undefined;
};

const WRITE = flag("--write");
const WINDOW_DAYS = opt("--window") ? parseInt(opt("--window")!, 10) : 30;

interface ReportRuleEntry {
  rule_id: string;
  fire_count: number;
  fp_dismissed_count: number;
  fp_confirmed_count: number;
  action_distribution?: Record<string, number>;
  confidence_buckets?: Record<string, number>;
}
interface RawReport {
  consumer_id: string;
  consumer_version?: string;
  report_period_start: string;
  report_period_end: string;
  atr_version: string;
  deployment_count: number;
  rules: ReportRuleEntry[];
}

interface RuleAggregate {
  total_fires_30d: number;
  fp_dismissed_30d: number;
  fp_confirmed_30d: number;
  fp_rate_30d: number;
  consumer_count_30d: number;
  deployment_count_30d: number;
  consumers: string[];
  first_seen: string;
  last_seen: string;
}

interface ConsumerAggregate {
  reports: number;
  rules_reporting: number;
  first_report: string;
  last_report: string;
}

function loadReports(): RawReport[] {
  if (!existsSync(REPORTS_DIR)) {
    console.error(
      `[aggregate-telemetry] reports dir not found: ${REPORTS_DIR}`,
    );
    return [];
  }
  const out: RawReport[] = [];
  for (const consumer of readdirSync(REPORTS_DIR)) {
    const consumerDir = join(REPORTS_DIR, consumer);
    let s;
    try {
      s = statSync(consumerDir);
    } catch {
      continue;
    }
    if (!s.isDirectory()) continue;
    for (const fname of readdirSync(consumerDir)) {
      if (!fname.endsWith(".json")) continue;
      const path = join(consumerDir, fname);
      try {
        const raw = readFileSync(path, "utf-8");
        const r = JSON.parse(raw) as RawReport;
        if (!r.consumer_id || !Array.isArray(r.rules)) continue;
        out.push(r);
      } catch (e) {
        console.error(`[aggregate-telemetry] could not parse ${path}: ${e}`);
        continue;
      }
    }
  }
  return out;
}

function withinWindow(report: RawReport, cutoff: Date): boolean {
  const end = new Date(report.report_period_end);
  return end >= cutoff;
}

function aggregate(reports: RawReport[]): {
  rules: Record<string, RuleAggregate>;
  consumers: Record<string, ConsumerAggregate>;
} {
  const now = Date.now();
  const cutoff = new Date(now - WINDOW_DAYS * 86400 * 1000);
  const inWindow = reports.filter((r) => withinWindow(r, cutoff));

  // Per-rule rollup
  const ruleConsumers = new Map<string, Set<string>>();
  const ruleDeployments = new Map<string, number>();
  const ruleFires = new Map<string, number>();
  const ruleFpDismissed = new Map<string, number>();
  const ruleFpConfirmed = new Map<string, number>();
  const ruleFirstSeen = new Map<string, string>();
  const ruleLastSeen = new Map<string, string>();

  for (const r of inWindow) {
    for (const rule of r.rules) {
      const id = rule.rule_id;
      ruleConsumers.set(
        id,
        (ruleConsumers.get(id) ?? new Set()).add(r.consumer_id),
      );
      ruleDeployments.set(
        id,
        (ruleDeployments.get(id) ?? 0) + r.deployment_count,
      );
      ruleFires.set(id, (ruleFires.get(id) ?? 0) + rule.fire_count);
      ruleFpDismissed.set(
        id,
        (ruleFpDismissed.get(id) ?? 0) + rule.fp_dismissed_count,
      );
      ruleFpConfirmed.set(
        id,
        (ruleFpConfirmed.get(id) ?? 0) + rule.fp_confirmed_count,
      );
      const periodEnd = r.report_period_end;
      const periodStart = r.report_period_start;
      const cur = ruleFirstSeen.get(id);
      if (!cur || periodStart < cur) ruleFirstSeen.set(id, periodStart);
      const last = ruleLastSeen.get(id);
      if (!last || periodEnd > last) ruleLastSeen.set(id, periodEnd);
    }
  }

  const rules: Record<string, RuleAggregate> = {};
  for (const id of ruleConsumers.keys()) {
    const fires = ruleFires.get(id) ?? 0;
    const dismissed = ruleFpDismissed.get(id) ?? 0;
    const confirmed = ruleFpConfirmed.get(id) ?? 0;
    rules[id] = {
      total_fires_30d: fires,
      fp_dismissed_30d: dismissed,
      fp_confirmed_30d: confirmed,
      fp_rate_30d: fires > 0 ? (dismissed + confirmed) / fires : 0,
      consumer_count_30d: ruleConsumers.get(id)!.size,
      deployment_count_30d: ruleDeployments.get(id) ?? 0,
      consumers: [...ruleConsumers.get(id)!].sort(),
      first_seen: ruleFirstSeen.get(id) ?? "",
      last_seen: ruleLastSeen.get(id) ?? "",
    };
  }

  // Per-consumer rollup
  const consumerReportCount = new Map<string, number>();
  const consumerRules = new Map<string, Set<string>>();
  const consumerFirst = new Map<string, string>();
  const consumerLast = new Map<string, string>();
  for (const r of inWindow) {
    consumerReportCount.set(
      r.consumer_id,
      (consumerReportCount.get(r.consumer_id) ?? 0) + 1,
    );
    const set = consumerRules.get(r.consumer_id) ?? new Set();
    for (const rule of r.rules) set.add(rule.rule_id);
    consumerRules.set(r.consumer_id, set);
    const start = r.report_period_start;
    const end = r.report_period_end;
    const cur = consumerFirst.get(r.consumer_id);
    if (!cur || start < cur) consumerFirst.set(r.consumer_id, start);
    const last = consumerLast.get(r.consumer_id);
    if (!last || end > last) consumerLast.set(r.consumer_id, end);
  }
  const consumers: Record<string, ConsumerAggregate> = {};
  for (const id of consumerReportCount.keys()) {
    consumers[id] = {
      reports: consumerReportCount.get(id) ?? 0,
      rules_reporting: consumerRules.get(id)?.size ?? 0,
      first_report: consumerFirst.get(id) ?? "",
      last_report: consumerLast.get(id) ?? "",
    };
  }

  return { rules, consumers };
}

function main(): void {
  const reports = loadReports();
  console.error(
    `[aggregate-telemetry] loaded ${reports.length} reports from ${REPORTS_DIR}`,
  );

  const { rules, consumers } = aggregate(reports);

  const ruleCount = Object.keys(rules).length;
  const consumerCount = Object.keys(consumers).length;
  console.error(
    `[aggregate-telemetry] window=${WINDOW_DAYS}d, ${ruleCount} rules, ${consumerCount} consumers reporting`,
  );

  const output = {
    computed_at: new Date().toISOString(),
    window_days: WINDOW_DAYS,
    reports_seen: reports.length,
    rules,
    consumers,
  };

  if (WRITE) {
    if (!existsSync(dirname(OUT_FILE)))
      mkdirSync(dirname(OUT_FILE), { recursive: true });
    writeFileSync(OUT_FILE, JSON.stringify(output, null, 2), "utf-8");
    console.error(
      `[aggregate-telemetry] wrote aggregate to ${OUT_FILE.replace(REPO_ROOT + "/", "")}`,
    );
  } else {
    console.log(JSON.stringify(output, null, 2));
  }

  console.log(
    `::aggregate-telemetry-summary::${JSON.stringify({
      reports_seen: reports.length,
      rules_with_telemetry: ruleCount,
      consumers_reporting: consumerCount,
    })}`,
  );
}

main();
