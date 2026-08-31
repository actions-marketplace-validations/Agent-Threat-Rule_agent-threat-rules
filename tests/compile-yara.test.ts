/**
 * Tests for the ATR→YARA compiler (scripts/compile-yara.ts).
 *
 * Verifies that the compilation contract in atr-method-v1.1.md §5.4
 * produces syntactically well-formed YARA rules.
 *
 * Run with: npx vitest tests/compile-yara.test.ts
 * (or via the main test runner: npm test)
 */

import { describe, it, expect } from 'vitest';
import { compileRule } from '../scripts/compile-yara.js';

describe('atr-to-yara compiler', () => {
  it('returns null for non-signature rules (skipped silently)', () => {
    const rule = {
      id: 'ATR-2026-99999',
      title: 'Pattern rule, not signature',
      severity: 'low',
      detection: {
        method: 'pattern',
        conditions: [{ field: 'content', operator: 'regex', value: 'foo' }],
        condition: 'any',
      },
    };
    expect(compileRule(rule)).toBeNull();
  });

  it('compiles a sha256 indicator to hash.sha256 module condition', () => {
    const rule = {
      id: 'ATR-2026-DRAFT-test-sha256',
      title: 'SHA256 hash test',
      severity: 'critical',
      status: 'draft',
      tags: { category: 'skill-compromise' },
      detection: {
        method: 'signature',
        signature: {
          indicators: [
            {
              type: 'sha256',
              value: '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8',
              target_field: 'skill.content',
            },
          ],
        },
      },
    };
    const out = compileRule(rule);
    expect(out).not.toBeNull();
    expect(out).toContain('import "hash"');
    expect(out).toContain('rule ATR_2026_DRAFT_test_sha256');
    expect(out).toContain('atr_id = "ATR-2026-DRAFT-test-sha256"');
    expect(out).toContain('atr_category = "skill-compromise"');
    expect(out).toContain('hash.sha256(0, filesize) == "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"');
  });

  it('compiles package_name to a YARA string with $ind0 reference', () => {
    const rule = {
      id: 'ATR-2026-DRAFT-test-pkg',
      title: 'Package name test',
      severity: 'high',
      detection: {
        method: 'signature',
        signature: {
          indicators: [
            {
              type: 'package_name',
              value: '@malicious/persistence-rootkit',
              target_field: 'skill.manifest.name',
            },
          ],
        },
      },
    };
    const out = compileRule(rule);
    expect(out).toContain('$ind0 = "@malicious/persistence-rootkit"');
    expect(out).toContain('strings:');
    // Single string ref → emit it directly, not `any of them`
    expect(out).toContain('$ind0');
  });

  it('combines multiple string indicators with `any of them` for match_logic any', () => {
    const rule = {
      id: 'ATR-2026-DRAFT-test-multi',
      title: 'Multi-indicator any',
      severity: 'critical',
      detection: {
        method: 'signature',
        signature: {
          match_logic: 'any',
          indicators: [
            { type: 'package_name', value: '@evil/a', target_field: 'skill.manifest.name' },
            { type: 'package_name', value: '@evil/b', target_field: 'skill.manifest.name' },
          ],
        },
      },
    };
    const out = compileRule(rule);
    expect(out).toContain('any of them');
    expect(out).toContain('$ind0 = "@evil/a"');
    expect(out).toContain('$ind1 = "@evil/b"');
  });

  it('combines multiple string indicators with `all of them` for match_logic all', () => {
    const rule = {
      id: 'ATR-2026-DRAFT-test-all',
      title: 'Multi-indicator all',
      severity: 'critical',
      detection: {
        method: 'signature',
        signature: {
          match_logic: 'all',
          indicators: [
            { type: 'package_name', value: '@a', target_field: 'skill.manifest.name' },
            { type: 'registry_url', value: 'https://malicious.example.com', target_field: 'skill.source_url' },
          ],
        },
      },
    };
    const out = compileRule(rule);
    expect(out).toContain('all of them');
  });

  it('mixes hash and string indicators with explicit and/or operators', () => {
    const rule = {
      id: 'ATR-2026-DRAFT-test-mixed',
      title: 'Mixed indicator types',
      severity: 'critical',
      detection: {
        method: 'signature',
        signature: {
          match_logic: 'any',
          indicators: [
            {
              type: 'sha256',
              value: 'abc123' + '0'.repeat(58),
              target_field: 'skill.content',
            },
            {
              type: 'package_name',
              value: '@malicious/pkg',
              target_field: 'skill.manifest.name',
            },
          ],
        },
      },
    };
    const out = compileRule(rule);
    // Mixed types cannot use `any of them` — must join with `or`
    expect(out).toContain('hash.sha256');
    expect(out).toContain('$ind1 = "@malicious/pkg"');
    expect(out).toMatch(/hash\.sha256[^]*?or[^]*?\$ind1/);
  });

  it('escapes YARA-significant characters in string values', () => {
    const rule = {
      id: 'ATR-2026-DRAFT-test-escape',
      title: 'Escape test "with quotes" and \\backslash',
      severity: 'medium',
      detection: {
        method: 'signature',
        signature: {
          indicators: [
            {
              type: 'package_name',
              value: 'pkg-with-"quote"-and\\backslash',
              target_field: 'skill.manifest.name',
            },
          ],
        },
      },
    };
    const out = compileRule(rule);
    expect(out).toContain('pkg-with-\\"quote\\"-and\\\\backslash');
    expect(out).toContain('Escape test \\"with quotes\\" and \\\\backslash');
  });

  it('lowercases hash values (canonical form per §5.3.1)', () => {
    const rule = {
      id: 'ATR-2026-DRAFT-test-case',
      title: 'Hash case normalization',
      severity: 'high',
      detection: {
        method: 'signature',
        signature: {
          indicators: [
            {
              type: 'sha256',
              value: 'ABCDEF1234567890' + '0'.repeat(48),
              target_field: 'skill.content',
            },
          ],
        },
      },
    };
    const out = compileRule(rule);
    expect(out).toContain('hash.sha256(0, filesize) == "abcdef1234567890');
    expect(out).not.toContain('ABCDEF1234567890');
  });

  it('throws on empty indicators array', () => {
    const rule = {
      id: 'ATR-2026-DRAFT-test-empty',
      title: 'Empty',
      severity: 'low',
      detection: { method: 'signature', signature: { indicators: [] } },
    };
    expect(() => compileRule(rule)).toThrow(/non-empty/);
  });

  it('throws on unknown indicator type', () => {
    const rule = {
      id: 'ATR-2026-DRAFT-test-unknown',
      title: 'Unknown',
      severity: 'low',
      detection: {
        method: 'signature',
        signature: {
          indicators: [{ type: 'unknown_type' as 'sha256', value: 'x', target_field: 'y' }],
        },
      },
    };
    expect(() => compileRule(rule)).toThrow(/unknown indicator type/);
  });

  it('emits compiler version metadata in meta block', () => {
    const rule = {
      id: 'ATR-2026-DRAFT-test-version',
      title: 'Version meta',
      severity: 'low',
      detection: {
        method: 'signature',
        signature: {
          indicators: [
            { type: 'package_name', value: 'x', target_field: 'y' },
          ],
        },
      },
    };
    const out = compileRule(rule);
    expect(out).toContain('compiler = "atr-to-yara@1.0.0"');
  });
});
