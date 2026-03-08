import { afterEach, describe, expect, test } from 'bun:test';
import type { StringFieldRef } from '../src/providers/types.js';
import { buildMaskedValue } from '../src/secrets/detector.js';
import { buildMaskedValuesBatch, setNativeScannerModuleForTests } from '../src/secrets/native.js';

function createField(value: string, contextKey?: string): StringFieldRef {
  return {
    id: 'field-1',
    path: 'session.value',
    sourceLabel: 'memory',
    value,
    maskPolicy: 'safe',
    contextKey,
    setValue() {},
  };
}

afterEach(() => {
  setNativeScannerModuleForTests(undefined);
});

describe('native scanner wrapper', () => {
  test('falls back to JavaScript scanning for lone surrogate code units', () => {
    let calls = 0;
    setNativeScannerModuleForTests({
      scanFieldsBatch() {
        calls += 1;
        return JSON.stringify({ results: [{ findings: [], nextValue: 'native-result' }] });
      },
    });

    const field = createField(`prefix\uD800suffix`, 'title');
    const [result] = buildMaskedValuesBatch([field]);

    expect(calls).toBe(0);
    expect(result).toEqual(buildMaskedValue(field));
  });

  test('falls back to JavaScript scanning when the native scanner throws', () => {
    setNativeScannerModuleForTests({
      scanFieldsBatch() {
        throw new Error('boom');
      },
    });

    const field = createField('sk-ant-1234567890abcdef', 'token');
    const [result] = buildMaskedValuesBatch([field]);

    expect(result).toEqual(buildMaskedValue(field));
  });
});
