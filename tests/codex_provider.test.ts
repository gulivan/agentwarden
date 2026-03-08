import { afterEach, describe, expect, test } from 'bun:test';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { codexProvider } from '../src/providers/codex.js';

let temporaryDirectory: string | undefined;
let previousSessionsDir: string | undefined;

afterEach(async () => {
  if (previousSessionsDir === undefined) {
    delete process.env.CODEX_SESSIONS_DIR;
  } else {
    process.env.CODEX_SESSIONS_DIR = previousSessionsDir;
  }

  previousSessionsDir = undefined;

  if (temporaryDirectory !== undefined) {
    await rm(temporaryDirectory, { force: true, recursive: true });
    temporaryDirectory = undefined;
  }
});

describe('Codex discovery', () => {
  test('warns when the first JSONL line exceeds the read limit', async () => {
    previousSessionsDir = process.env.CODEX_SESSIONS_DIR;
    temporaryDirectory = await mkdtemp(path.join(tmpdir(), 'agentwarden-codex-'));
    process.env.CODEX_SESSIONS_DIR = temporaryDirectory;

    const longLinePath = path.join(temporaryDirectory, 'too-long.jsonl');
    await writeFile(longLinePath, 'x'.repeat(1024 * 1024 + 1), 'utf8');

    const discovery = await codexProvider.discoverSessions();

    expect(discovery.sessions).toHaveLength(0);
    expect(discovery.warnings.some((warning) => warning.message.includes('first JSONL line exceeds'))).toBe(true);
  });
});
