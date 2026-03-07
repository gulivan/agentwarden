import { describe, expect, test } from 'bun:test';
import type { Key } from 'node:readline';
import { cleanupRawMenuInput, type RawMenuInputController } from '../src/commands/interactive_scan.js';

describe('cleanupRawMenuInput', () => {
  test('pauses stdin and restores raw mode when menu enabled it', () => {
    const calls: string[] = [];
    const handleKeypress = (_sequence: string, _key: Key): void => undefined;
    const input: RawMenuInputController = {
      isTTY: true,
      off(eventName, listener) {
        expect(eventName).toBe('keypress');
        expect(listener).toBe(handleKeypress);
        calls.push('off');
      },
      pause() {
        calls.push('pause');
      },
      setRawMode(mode) {
        expect(mode).toBe(false);
        calls.push('setRawMode:false');
      },
    };

    cleanupRawMenuInput(input, handleKeypress, false);

    expect(calls).toEqual(['off', 'setRawMode:false', 'pause']);
  });

  test('still pauses stdin when raw mode was already enabled', () => {
    const calls: string[] = [];
    const handleKeypress = (_sequence: string, _key: Key): void => undefined;
    const input: RawMenuInputController = {
      isTTY: true,
      off() {
        calls.push('off');
      },
      pause() {
        calls.push('pause');
      },
      setRawMode() {
        calls.push('setRawMode');
      },
    };

    cleanupRawMenuInput(input, handleKeypress, true);

    expect(calls).toEqual(['off', 'pause']);
  });
});
