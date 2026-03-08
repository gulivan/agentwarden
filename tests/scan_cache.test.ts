import { afterEach, describe, expect, test } from 'bun:test';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { ScanCache } from '../src/io/scan_cache.js';
import { resolveSecretTypeSelection } from '../src/secrets/options.js';
import type { SessionHandle } from '../src/providers/types.js';

let temporaryDirectory: string | undefined;

afterEach(async () => {
  delete process.env.AGENTWARDEN_SCAN_CACHE_PATH;

  if (temporaryDirectory !== undefined) {
    await rm(temporaryDirectory, { force: true, recursive: true });
    temporaryDirectory = undefined;
  }
});

describe('scan cache', () => {
  test('returns cached findings until the source file changes', async () => {
    temporaryDirectory = await mkdtemp(path.join(tmpdir(), 'agentwarden-cache-'));
    const sessionPath = path.join(temporaryDirectory, 'session.jsonl');
    const cachePath = path.join(temporaryDirectory, 'scan-cache.json');
    process.env.AGENTWARDEN_SCAN_CACHE_PATH = cachePath;

    await writeFile(sessionPath, '{"type":"session_meta"}\n', 'utf8');

    const handle: SessionHandle = {
      provider: 'codex',
      sessionId: 'session-1',
      location: sessionPath,
    };

    const selection = resolveSecretTypeSelection();
    const cache = await ScanCache.load(selection);

    await cache.set(handle, {
      findings: [
        {
          fingerprint: 'abc123',
          preview: 'sk-ant****cdef',
          rawSample: 'sk-ant-1234567890abcdef',
          type: 'raw_token',
        },
      ],
      hasChanges: true,
    });
    await cache.persist();

    const warmCache = await ScanCache.load(selection);
    expect(await warmCache.get(handle)).toEqual({
      findings: [
        {
          fingerprint: 'abc123',
          preview: 'sk-ant****cdef',
          rawSample: 'sk-ant-1234567890abcdef',
          type: 'raw_token',
        },
      ],
      hasChanges: true,
    });

    await writeFile(sessionPath, '{"type":"session_meta"}\n{"extra":true}\n', 'utf8');
    expect(await warmCache.get(handle)).toBeUndefined();
  });
});
