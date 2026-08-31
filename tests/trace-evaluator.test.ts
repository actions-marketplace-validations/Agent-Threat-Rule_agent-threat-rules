/**
 * Tests for src/trace-evaluator.ts.
 * Verifies the formal semantics defined in atr-method-v1.1.md §8.
 */

import { describe, it, expect } from "vitest";
import { evaluateTraceRule } from "../src/trace-evaluator.js";
import type { ATRRule, ATRTrace } from "../src/types.js";

function ruleWithTrace(detection: Partial<ATRRule["detection"]>): ATRRule {
  return {
    title: "test rule",
    id: "ATR-2026-TEST",
    status: "draft",
    description: "test",
    author: "test",
    date: "2026/05/28",
    severity: "high",
    tags: { category: "agent-manipulation" },
    agent_source: { type: "agent_trace" },
    detection: {
      conditions: [],
      condition: "any",
      method: "trace",
      ...detection,
    },
    response: { actions: ["alert"] },
  } as unknown as ATRRule;
}

describe("trace-evaluator: forbid primitive (§8.3.1)", () => {
  it("matches when shape appears AND preceded_by predecessor exists", () => {
    const rule = ruleWithTrace({
      trace: {
        ingest_format: "openinference",
        forbid: [
          {
            shape: {
              "span.kind": "TOOL",
              attributes: { "tool.privilege": { in: ["write", "destructive", "exfil"] } },
            },
            preceded_by: {
              "span.kind": "RETRIEVER",
              attributes: { "source.trust": "untrusted" },
            },
          },
        ],
      },
    });
    const trace: ATRTrace = {
      spans: [
        { id: "r1", "span.kind": "RETRIEVER", attributes: { "source.trust": "untrusted" } },
        { id: "t1", "span.kind": "TOOL", attributes: { "tool.privilege": "exfil" } },
      ],
    };
    const result = evaluateTraceRule(rule, trace);
    expect(result.matched).toBe(true);
    expect(result.matchedPrimitives).toContain("forbid");
  });

  it("does NOT match when shape appears but predecessor missing", () => {
    const rule = ruleWithTrace({
      trace: {
        forbid: [
          {
            shape: { "span.kind": "TOOL", attributes: { "tool.privilege": "exfil" } },
            preceded_by: {
              "span.kind": "RETRIEVER",
              attributes: { "source.trust": "untrusted" },
            },
          },
        ],
      },
    });
    const trace: ATRTrace = {
      spans: [
        { id: "t1", "span.kind": "TOOL", attributes: { "tool.privilege": "exfil" } },
      ],
    };
    const result = evaluateTraceRule(rule, trace);
    expect(result.matched).toBe(false);
  });

  it("does NOT match when predecessor appears AFTER target (temporal order matters)", () => {
    const rule = ruleWithTrace({
      trace: {
        forbid: [
          {
            shape: { "span.kind": "TOOL", attributes: { "tool.privilege": "exfil" } },
            preceded_by: {
              "span.kind": "RETRIEVER",
              attributes: { "source.trust": "untrusted" },
            },
          },
        ],
      },
    });
    const trace: ATRTrace = {
      spans: [
        { id: "t1", "span.kind": "TOOL", attributes: { "tool.privilege": "exfil" } },
        { id: "r1", "span.kind": "RETRIEVER", attributes: { "source.trust": "untrusted" } },
      ],
    };
    const result = evaluateTraceRule(rule, trace);
    expect(result.matched).toBe(false);
  });

  it("matches `forbid` without preceded_by — span shape alone is forbidden", () => {
    const rule = ruleWithTrace({
      trace: {
        forbid: [
          { shape: { "span.kind": "TOOL", attributes: { "tool.name": "rm_rf_slash" } } },
        ],
      },
    });
    const trace: ATRTrace = {
      spans: [
        { id: "t1", "span.kind": "TOOL", attributes: { "tool.name": "rm_rf_slash" } },
      ],
    };
    expect(evaluateTraceRule(rule, trace).matched).toBe(true);
  });
});

describe("trace-evaluator: require primitive (§8.3.2 inverse polarity)", () => {
  it("matches (violation) when target appears WITHOUT required predecessor", () => {
    const rule = ruleWithTrace({
      trace: {
        require: [
          {
            target_shape: { "span.kind": "TOOL", attributes: { "tool.privilege": "destructive" } },
            must_be_preceded_by: {
              "span.kind": "AGENT",
              attributes: { human_approval: true },
            },
          },
        ],
      },
    });
    const trace: ATRTrace = {
      spans: [
        { id: "t1", "span.kind": "TOOL", attributes: { "tool.privilege": "destructive" } },
      ],
    };
    const result = evaluateTraceRule(rule, trace);
    expect(result.matched).toBe(true);
    expect(result.matchedPrimitives).toContain("require");
  });

  it("does NOT match when target appears WITH required predecessor", () => {
    const rule = ruleWithTrace({
      trace: {
        require: [
          {
            target_shape: { "span.kind": "TOOL", attributes: { "tool.privilege": "destructive" } },
            must_be_preceded_by: {
              "span.kind": "AGENT",
              attributes: { human_approval: true },
            },
          },
        ],
      },
    });
    const trace: ATRTrace = {
      spans: [
        { id: "a1", "span.kind": "AGENT", attributes: { human_approval: true } },
        { id: "t1", "span.kind": "TOOL", attributes: { "tool.privilege": "destructive" } },
      ],
    };
    expect(evaluateTraceRule(rule, trace).matched).toBe(false);
  });

  it("supports one_of_shapes disjunction for must_be_preceded_by", () => {
    const rule = ruleWithTrace({
      trace: {
        require: [
          {
            target_shape: { "span.kind": "TOOL", attributes: { "tool.privilege": "destructive" } },
            must_be_preceded_by: {
              one_of_shapes: [
                { "span.kind": "HUMAN" },
                { "span.kind": "AGENT", attributes: { human_approval: true } },
              ],
            },
          },
        ],
      },
    });
    // HUMAN span satisfies disjunction
    const trace1: ATRTrace = {
      spans: [
        { id: "h1", "span.kind": "HUMAN", attributes: {} },
        { id: "t1", "span.kind": "TOOL", attributes: { "tool.privilege": "destructive" } },
      ],
    };
    expect(evaluateTraceRule(rule, trace1).matched).toBe(false);

    // AGENT with human_approval=true also satisfies
    const trace2: ATRTrace = {
      spans: [
        { id: "a1", "span.kind": "AGENT", attributes: { human_approval: true } },
        { id: "t1", "span.kind": "TOOL", attributes: { "tool.privilege": "destructive" } },
      ],
    };
    expect(evaluateTraceRule(rule, trace2).matched).toBe(false);

    // Neither satisfies — violation
    const trace3: ATRTrace = {
      spans: [
        { id: "a1", "span.kind": "AGENT", attributes: {} },
        { id: "t1", "span.kind": "TOOL", attributes: { "tool.privilege": "destructive" } },
      ],
    };
    expect(evaluateTraceRule(rule, trace3).matched).toBe(true);
  });
});

describe("trace-evaluator: invariant primitive (§8.3.3)", () => {
  it("matches (violation) when attribute drifts across delegation chain", () => {
    const rule = ruleWithTrace({
      trace: {
        invariant: [{ attribute: "session.id", across: "agent.delegation_chain" }],
      },
    });
    const trace: ATRTrace = {
      spans: [
        {
          id: "s1",
          "span.kind": "AGENT",
          attributes: { "session.id": "sess_A", "agent.delegation_chain": "chain_1" },
        },
        {
          id: "s2",
          "span.kind": "AGENT",
          attributes: { "session.id": "sess_B", "agent.delegation_chain": "chain_1" },
        },
      ],
    };
    expect(evaluateTraceRule(rule, trace).matched).toBe(true);
  });

  it("does NOT match when attribute is constant", () => {
    const rule = ruleWithTrace({
      trace: { invariant: [{ attribute: "session.id", across: "agent.delegation_chain" }] },
    });
    const trace: ATRTrace = {
      spans: [
        { id: "s1", attributes: { "session.id": "sess_A", "agent.delegation_chain": "c" } },
        { id: "s2", attributes: { "session.id": "sess_A", "agent.delegation_chain": "c" } },
      ],
    };
    expect(evaluateTraceRule(rule, trace).matched).toBe(false);
  });

  it("scopes invariant per group_by key — different chains don't cross-pollute", () => {
    const rule = ruleWithTrace({
      trace: { invariant: [{ attribute: "session.id", across: "agent.delegation_chain" }] },
    });
    const trace: ATRTrace = {
      spans: [
        { id: "s1", attributes: { "session.id": "sess_A", "agent.delegation_chain": "chain_1" } },
        { id: "s2", attributes: { "session.id": "sess_B", "agent.delegation_chain": "chain_2" } },
      ],
    };
    expect(evaluateTraceRule(rule, trace).matched).toBe(false);
  });

  it("does NOT match on single-span chains (no second value to compare)", () => {
    const rule = ruleWithTrace({
      trace: { invariant: [{ attribute: "session.id", across: "agent.delegation_chain" }] },
    });
    const trace: ATRTrace = {
      spans: [{ id: "alone", attributes: { "session.id": "x", "agent.delegation_chain": "c" } }],
    };
    expect(evaluateTraceRule(rule, trace).matched).toBe(false);
  });
});

describe("trace-evaluator: cross-attribute references (§8.3)", () => {
  it("resolves ${span.attributes.X} placeholder against the candidate span", () => {
    const rule = ruleWithTrace({
      trace: {
        forbid: [
          {
            shape: {
              "span.kind": "TOOL",
              attributes: {
                "tool.name": { in: ["memory.write"] },
                "tool.args.target_conversation_id": {
                  not_equals: "${span.attributes.conversation.id}",
                },
              },
            },
          },
        ],
      },
    });
    // target_conversation_id differs from conversation.id → violation
    const traceViolation: ATRTrace = {
      spans: [
        {
          id: "t1",
          "span.kind": "TOOL",
          attributes: {
            "tool.name": "memory.write",
            "conversation.id": "conv_A",
            "tool.args.target_conversation_id": "conv_B",
          },
        },
      ],
    };
    expect(evaluateTraceRule(rule, traceViolation).matched).toBe(true);

    // target_conversation_id equals conversation.id → no violation
    const traceOk: ATRTrace = {
      spans: [
        {
          id: "t1",
          "span.kind": "TOOL",
          attributes: {
            "tool.name": "memory.write",
            "conversation.id": "same",
            "tool.args.target_conversation_id": "same",
          },
        },
      ],
    };
    expect(evaluateTraceRule(rule, traceOk).matched).toBe(false);
  });
});

describe("trace-evaluator: predicate vocabulary (§8.3)", () => {
  it("supports `in` predicate", () => {
    const rule = ruleWithTrace({
      trace: {
        forbid: [
          {
            shape: {
              "span.kind": "TOOL",
              attributes: { "tool.privilege": { in: ["write", "destructive", "exfil"] } },
            },
          },
        ],
      },
    });
    expect(
      evaluateTraceRule(rule, {
        spans: [{ id: "t1", "span.kind": "TOOL", attributes: { "tool.privilege": "destructive" } }],
      }).matched,
    ).toBe(true);
    expect(
      evaluateTraceRule(rule, {
        spans: [{ id: "t1", "span.kind": "TOOL", attributes: { "tool.privilege": "read" } }],
      }).matched,
    ).toBe(false);
  });

  it("supports `exists` predicate", () => {
    const rule = ruleWithTrace({
      trace: {
        forbid: [
          {
            shape: {
              "span.kind": "TOOL",
              attributes: { "tool.args.target_conversation_id": { exists: true } },
            },
          },
        ],
      },
    });
    expect(
      evaluateTraceRule(rule, {
        spans: [{ id: "t1", "span.kind": "TOOL", attributes: { "tool.args.target_conversation_id": "x" } }],
      }).matched,
    ).toBe(true);
    expect(
      evaluateTraceRule(rule, {
        spans: [{ id: "t1", "span.kind": "TOOL", attributes: {} }],
      }).matched,
    ).toBe(false);
  });
});

describe("trace-evaluator: determinism (§8.5)", () => {
  it("returns identical result on repeated evaluation", () => {
    const rule = ruleWithTrace({
      trace: { invariant: [{ attribute: "user.id", across: "agent.delegation_chain" }] },
    });
    const trace: ATRTrace = {
      spans: [
        { id: "s1", attributes: { "user.id": "alice", "agent.delegation_chain": "c" } },
        { id: "s2", attributes: { "user.id": "bob", "agent.delegation_chain": "c" } },
      ],
    };
    const r1 = evaluateTraceRule(rule, trace);
    const r2 = evaluateTraceRule(rule, trace);
    expect(r1).toEqual(r2);
  });
});
