import { afterEach, describe, expect, test } from 'bun:test';
import { mkdtemp, readFile, rm, stat, utimes, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { ScanCache } from '../src/io/scan_cache.js';
import { resolveSecretTypeSelection } from '../src/secrets/options.js';
import type { SessionHandle } from '../src/providers/types.js';

let temporaryDirectory: string | undefined;

afterEach(async () => {
  delete process.env.AGENTWARDEN_SCAN_CACHE_PATH;
  delete process.env.AGENTWARDEN_DISABLE_SCAN_CACHE;

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
          type: 'raw_token',
        },
      ],
      hasChanges: true,
    });
    await cache.persist();

    expect(await readFile(cachePath, 'utf8')).not.toContain('sk-ant-1234567890abcdef');

    const warmCache = await ScanCache.load(selection);
    expect(await warmCache.get(handle)).toEqual({
      findings: [
        {
          fingerprint: 'abc123',
          preview: 'sk-ant****cdef',
          type: 'raw_token',
        },
      ],
      hasChanges: true,
    });

    await writeFile(sessionPath, '{"type":"session_meta"}\n{"extra":true}\n', 'utf8');
    expect(await warmCache.get(handle)).toBeUndefined();
  });

  test('ignores disabled cache mode', async () => {
    temporaryDirectory = await mkdtemp(path.join(tmpdir(), 'agentwarden-cache-'));
    const sessionPath = path.join(temporaryDirectory, 'session.jsonl');
    const cachePath = path.join(temporaryDirectory, 'scan-cache.json');
    process.env.AGENTWARDEN_SCAN_CACHE_PATH = cachePath;
    process.env.AGENTWARDEN_DISABLE_SCAN_CACHE = '1';

    await writeFile(sessionPath, '{"type":"session_meta"}\n', 'utf8');

    const handle: SessionHandle = {
      provider: 'codex',
      sessionId: 'session-1',
      location: sessionPath,
    };

    const cache = await ScanCache.load(resolveSecretTypeSelection());
    await cache.set(handle, {
      findings: [{ fingerprint: 'abc123', preview: 'sk-ant****cdef', type: 'raw_token' }],
      hasChanges: false,
    });
    await cache.persist();

    expect(await ScanCache.load(resolveSecretTypeSelection()).then((next) => next.get(handle))).toBeUndefined();
  });

  test('invalidates cache entries after a same-size rewrite even when mtime is restored', async () => {
    temporaryDirectory = await mkdtemp(path.join(tmpdir(), 'agentwarden-cache-'));
    const sessionPath = path.join(temporaryDirectory, 'session.jsonl');
    const cachePath = path.join(temporaryDirectory, 'scan-cache.json');
    process.env.AGENTWARDEN_SCAN_CACHE_PATH = cachePath;

    const originalContent = '{"type":"session_meta","token":"aaaaaaaaaaaaaaaa"}\n';
    const rewrittenContent = '{"type":"session_meta","token":"bbbbbbbbbbbbbbbb"}\n';
    await writeFile(sessionPath, originalContent, 'utf8');

    const handle: SessionHandle = {
      provider: 'codex',
      sessionId: 'session-1',
      location: sessionPath,
    };

    const selection = resolveSecretTypeSelection();
    const cache = await ScanCache.load(selection);
    await cache.set(handle, {
      findings: [{ fingerprint: 'abc123', preview: 'sk-ant****cdef', type: 'raw_token' }],
      hasChanges: true,
    });
    await cache.persist();

    const beforeRewrite = await stat(sessionPath);
    await writeFile(sessionPath, rewrittenContent, 'utf8');
    await utimes(sessionPath, beforeRewrite.atime, beforeRewrite.mtime);

    const warmCache = await ScanCache.load(selection);
    expect(await warmCache.get(handle)).toBeUndefined();
  });

  test('skips corrupted cache entries', async () => {
    temporaryDirectory = await mkdtemp(path.join(tmpdir(), 'agentwarden-cache-'));
    const sessionPath = path.join(temporaryDirectory, 'session.jsonl');
    const cachePath = path.join(temporaryDirectory, 'scan-cache.json');
    process.env.AGENTWARDEN_SCAN_CACHE_PATH = cachePath;

    await writeFile(sessionPath, '{"type":"session_meta"}\n', 'utf8');
    await writeFile(
      cachePath,
      JSON.stringify({
        version: 5,
        entries: {
          broken: {
            findings: [{ fingerprint: 'abc123', preview: 'sk-ant****cdef', type: 'raw_token' }],
            fingerprint: null,
            hasChanges: true,
          },
        },
      }),
      'utf8',
    );

    const handle: SessionHandle = {
      provider: 'codex',
      sessionId: 'session-1',
      location: sessionPath,
    };

    const cache = await ScanCache.load(resolveSecretTypeSelection());
    await expect(cache.get(handle)).resolves.toBeUndefined();
  });
});
