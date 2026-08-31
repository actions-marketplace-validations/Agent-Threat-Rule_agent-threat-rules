#!/usr/bin/env node
/**
 * Export selected ATR rules to Sage's `threats/agent-layer.yaml` format.
 *
 * This script is the human-runnable companion to the
 * `agent-threat-rules/converters/sage` API. It loads a curated set of ATR
 * rules, converts them to Sage's schema, and emits a YAML fragment with the
 * file header + rule list. Output is written to stdout (or to --out path)
 * for the Sage maintainer to drop into `threats/agent-layer.yaml`.
 *
 * Usage:
 *   tsx scripts/export-sage.ts --selection=preset:gap-fill-2026-05-12
 *   tsx scripts/export-sage.ts --rules=ATR-2026-00441,ATR-2026-00098 --out=agent-layer-fragment.yaml
 *
 * Presets:
 *   gap-fill-2026-05-12  6 rules in privilege_escalation/excessive_autonomy/
 *                       agent_manipulation/model_abuse — categories not yet in
 *                       Sage's existing 27 rules (per audit of pre-release branch
 *                       on 2026-05-12).
 *
 * The Sage maintainer (Vaclav Belak) is the final decision-maker on whether
 * the output gets merged. This script only generates a proposal.
 *
 * @module agent-threat-rules/scripts/export-sage
 */

import { join } from 'node:path';
import { writeFileSync, readdirSync, statSync } from 'node:fs';
import { loadRuleFile } from '../src/loader.js';
import {
	atrToSageBatch,
	sageRulesToYaml,
} from '../src/converters/sage.js';
import type { ATRRule } from '../src/types.js';

interface CliArgs {
	readonly selection: 'preset:gap-fill-2026-05-12' | null;
	readonly explicitRules: readonly string[];
	readonly out: string | null;
	readonly header: boolean;
}

function parseArgs(argv: readonly string[]): CliArgs {
	let selection: CliArgs['selection'] = null;
	let explicitRules: string[] = [];
	let out: string | null = null;
	let header = true;
	for (const arg of argv.slice(2)) {
		if (arg.startsWith('--selection=')) {
			const val = arg.slice('--selection='.length);
			if (val === 'preset:gap-fill-2026-05-12') {
				selection = 'preset:gap-fill-2026-05-12';
			} else {
				throw new Error(`Unknown selection: ${val}`);
			}
		} else if (arg.startsWith('--rules=')) {
			explicitRules = arg.slice('--rules='.length).split(',').map((s) => s.trim());
		} else if (arg.startsWith('--out=')) {
			out = arg.slice('--out='.length);
		} else if (arg === '--no-header') {
			header = false;
		} else if (arg === '--help' || arg === '-h') {
			printHelp();
			process.exit(0);
		}
	}
	return { selection, explicitRules, out, header };
}

function printHelp(): void {
	console.log(`Usage: tsx scripts/export-sage.ts [options]

Options:
  --selection=preset:NAME       Use a named preset selection (see below)
  --rules=ATR-...,ATR-...       Comma-separated list of ATR ids to export
  --out=PATH                    Write YAML output to PATH (default: stdout)
  --no-header                   Skip the file-level YAML comment header
  --help, -h                    Show this help

Presets:
  gap-fill-2026-05-12   6 rules in categories not yet covered by Sage's
                        existing 27 agent-layer rules

This script is read-only on the ATR rule corpus. It does not mutate any ATR
state. The output is a YAML fragment intended to be reviewed by a Sage
maintainer and dropped into gendigitalinc/sage threats/agent-layer.yaml.
`);
}

/**
 * Curated 6-rule selection covering Sage's gap categories. Each id maps to
 * a known-good ATR rule chosen for: (1) high precision in ATR's own
 * benchmark, (2) coverage of a category Sage's existing 27 rules do not
 * yet touch, (3) clean single-condition or simple multi-condition structure
 * suitable for Sage's single-pattern schema.
 */
/**
 * 2026-05-12 selection — privilege_escalation category only.
 *
 * Three ATR sources chosen as the smallest cohesive PR demonstrating the
 * bridge:
 *
 *   ATR-2026-00441   Microsoft Semantic Kernel SessionsPythonPlugin
 *                    CVE-2026-25592 (MSRC disclosure 2026-05-07). 5 detection
 *                    conditions covering autostart paths, SK identifiers,
 *                    descriptor patterns, file-write call sites, and
 *                    Windows registry Run-key persistence. The bridge splits
 *                    these into 5 Sage rules with -a..-e suffixes to stay
 *                    under Sage's regex-length convention.
 *
 *   ATR-2026-00110   eval() / new Function / vm.runIn with untrusted input.
 *                    Single condition; produces 1 Sage rule.
 *
 *   ATR-2026-00111   Shell metacharacter injection ($(...), pipe-to-shell).
 *                    Single condition; produces 1 Sage rule.
 *
 * Other gap categories (excessive_autonomy, agent_manipulation, model_abuse)
 * are intentionally deferred to follow-up PRs to keep this initial bridge PR
 * focused on a single category and a manageable review surface.
 */
const GAP_FILL_2026_05_12: readonly string[] = Object.freeze([
	'ATR-2026-00441',
	'ATR-2026-00110',
	'ATR-2026-00111',
]);

/**
 * Map an ATR id to its YAML file path on disk. Iterates the rules/ tree
 * since the directory layout puts each rule in a subfolder by category.
 */
function findRulePath(rulesRoot: string, atrId: string): string {
	const subdirs = readdirSync(rulesRoot).filter((entry) =>
		statSync(join(rulesRoot, entry)).isDirectory(),
	);
	for (const sub of subdirs) {
		const dir = join(rulesRoot, sub);
		const files = readdirSync(dir);
		for (const f of files) {
			if (f.startsWith(`${atrId}-`) || f === `${atrId}.yaml`) {
				return join(dir, f);
			}
		}
	}
	throw new Error(`Rule file not found for ${atrId} under ${rulesRoot}`);
}

function loadByIds(rulesRoot: string, ids: readonly string[]): ATRRule[] {
	return ids.map((id) => loadRuleFile(findRulePath(rulesRoot, id)));
}

function buildHeader(): string {
	const now = new Date();
	const dateStr = `${now.getUTCFullYear()}-${String(now.getUTCMonth() + 1).padStart(2, '0')}-${String(now.getUTCDate()).padStart(2, '0')}`;
	return `# Agent-layer threat patterns for Sage — additional coverage
#
# Generated: ${dateStr} via agent-threat-rules/converters/sage
# Author: ATR (Agent Threat Rules) community contributors
# Upstream: https://github.com/Agent-Threat-Rule/agent-threat-rules
#
# License: Detection Rule License (DRL) 1.1 (Sage threats/ convention).
# Upstream rules are MIT-licensed; the converter preserves attribution per
# both licenses in the per-rule comment block below.
#
# This fragment was produced by:
#   tsx scripts/export-sage.ts --selection=preset:gap-fill-2026-05-12
#
# Each rule below has a corresponding ATR rule referenced in the # Upstream:
# comment. To re-import a rule after upstream changes, re-run the same
# script with the same selection.
#
# Coverage added (gaps vs Sage's existing 27 agent-layer rules):
#   privilege_escalation: 3 ATR source rules covering Microsoft Semantic
#     Kernel CVE-2026-25592 (disclosed by MSRC 2026-05-07), eval/new Function
#     dynamic-code injection, and shell metacharacter injection in tool args.
#
# The Microsoft Semantic Kernel rule (ATR-2026-00441) has 5 detection
# conditions that exceed Sage's regex-length convention when combined; the
# converter splits them into 5 sister Sage rules (CLT-PRV-001a..-001e) that
# share the same numeric base and the same # Upstream: provenance comment.
# Sage maintainers can disable individual sub-rules via the standard
# revoked: true flag if needed.
#
# Other gap categories (excessive_autonomy, agent_manipulation, model_abuse)
# are intentionally deferred to follow-up PRs.
`;
}

function main(): void {
	const args = parseArgs(process.argv);

	if (args.selection === null && args.explicitRules.length === 0) {
		console.error('Error: --selection or --rules must be provided');
		printHelp();
		process.exit(1);
	}

	const rulesRoot = join(process.cwd(), 'rules');
	const ids =
		args.selection === 'preset:gap-fill-2026-05-12'
			? GAP_FILL_2026_05_12
			: args.explicitRules;

	const atrRules = loadByIds(rulesRoot, ids);
	const { rules: sageRules, warnings } = atrToSageBatch(atrRules);

	// Print warnings to stderr so they show up during PR prep but do not
	// contaminate the YAML output on stdout.
	if (warnings.length > 0) {
		console.error(`[export-sage] ${warnings.length} conversion warnings:`);
		for (const w of warnings) {
			console.error(`  ${w.ruleId} [${w.kind}]: ${w.detail}`);
		}
	}

	const yaml =
		(args.header ? buildHeader() + '\n' : '') + sageRulesToYaml(sageRules);

	if (args.out) {
		writeFileSync(args.out, yaml + '\n', 'utf-8');
		console.error(`[export-sage] wrote ${sageRules.length} rules to ${args.out}`);
	} else {
		process.stdout.write(yaml + '\n');
	}
}

main();
