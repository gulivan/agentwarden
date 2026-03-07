import { describe, expect, test } from 'bun:test';
import type { SessionArtifact, StringFieldRef } from '../src/providers/types.js';
import { buildMaskedValue } from '../src/secrets/detector.js';
import { analyzeArtifacts } from '../src/secrets/plan.js';

function createArtifact(options: {
  contextKey?: string;
  maskPolicy?: StringFieldRef['maskPolicy'];
  value: string;
}): SessionArtifact {
  const field: StringFieldRef = {
    id: 'field-1',
    path: 'session.title',
    sourceLabel: 'memory',
    value: options.value,
    maskPolicy: options.maskPolicy ?? 'safe',
    contextKey: options.contextKey,
    setValue(nextValue: string) {
      field.value = nextValue;
    },
  };

  return {
    handle: {
      provider: 'codex',
      sessionId: 'session-1',
      location: '/tmp/session-1.jsonl',
    },
    fields: [field],
    warnings: [],
    backupTargets: [],
    async writeChanges() {
      return { writes: [], warnings: [] };
    },
  };
}

describe('mask planning', () => {
  test('masks conditional fields when the value is only the secret', () => {
    const artifact = createArtifact({
      value: '"sk-ant-1234567890abcdef"',
      contextKey: 'title',
      maskPolicy: 'conditional',
    });

    const analysis = analyzeArtifacts([artifact]);

    expect(analysis.summary.sessionsWithChanges).toBe(1);
    expect(analysis.analyzedSessions[0]?.fieldPlans).toHaveLength(1);
    expect(analysis.analyzedSessions[0]?.fieldPlans[0]?.nextValue).toBe('"sk-ant****cdef"');
  });

  test('does not mask conditional fields when surrounding text remains', () => {
    const artifact = createArtifact({
      value: 'Release title sk-ant-1234567890abcdef',
      contextKey: 'title',
      maskPolicy: 'conditional',
    });

    const analysis = analyzeArtifacts([artifact]);

    expect(analysis.summary.findings).toBe(1);
    expect(analysis.summary.sessionsWithChanges).toBe(0);
    expect(analysis.analyzedSessions[0]?.fieldPlans).toHaveLength(0);
  });

  test('never masks report-only fields', () => {
    const artifact = createArtifact({
      value: '/Users/alice/.codex/sessions',
      contextKey: 'path',
      maskPolicy: 'report_only',
    });

    const analysis = analyzeArtifacts([artifact]);

    expect(analysis.summary.findings).toBe(1);
    expect(analysis.summary.sessionsWithChanges).toBe(0);
    expect(analysis.analyzedSessions[0]?.fieldPlans).toHaveLength(0);
  });
});

describe('nested JSON masking', () => {
  test('masks repeated nested JSON secrets while keeping JSON valid', () => {
    const privateKey = ['-----BEGIN PRIVATE KEY-----', 'ABCDEF1234567890', '-----END PRIVATE KEY-----'].join('\n');
    const nested = JSON.stringify({ key: privateKey });
    const value = JSON.stringify({ first: nested, second: nested });

    const masked = buildMaskedValue(
      {
        id: 'field-1',
        path: 'session.payload',
        sourceLabel: 'memory',
        value,
        maskPolicy: 'safe',
        contextKey: 'payload',
        setValue() {},
      },
      undefined,
    ).nextValue;

    const parsed = JSON.parse(masked) as { first: string; second: string };

    expect(JSON.parse(parsed.first)).toEqual({ key: '[PRIVATE KEY REDACTED]' });
    expect(JSON.parse(parsed.second)).toEqual({ key: '[PRIVATE KEY REDACTED]' });
  });
});
