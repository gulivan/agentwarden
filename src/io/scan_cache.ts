import { createHash } from 'node:crypto';
import { open, readFile, stat } from 'node:fs/promises';
import path from 'node:path';
import { ensurePrivateDir, expandHomeDir, pathExists, writePrivateFile } from './paths.js';
import type { SessionHandle } from '../providers/types.js';
import type { ResolvedSecretTypeSelection } from '../secrets/options.js';
import type { ScanFinding } from '../secrets/plan.js';

const SCAN_CACHE_VERSION = 5;
const CONTENT_PROBE_BYTES = 4096;

function getScanCachePath(): string {
  return expandHomeDir(process.env.AGENTWARDEN_SCAN_CACHE_PATH ?? '~/.agentwarden/cache/scan-results-v5.json');
}

interface CacheLocationFingerprint {
  contentProbeHash: string;
  ctimeMs: number;
  mtimeMs: number;
  size: number;
}

interface CacheEntry {
  findings: ScanFinding[];
  fingerprint: CacheLocationFingerprint;
  hasChanges: boolean;
}

interface CacheFile {
  entries: Record<string, CacheEntry>;
  version: number;
}

export interface CachedSessionAnalysis {
  findings: ScanFinding[];
  hasChanges: boolean;
}

async function getLocationFingerprint(location: string): Promise<CacheLocationFingerprint | undefined> {
  let handle;

  try {
    const metadata = await stat(location);
    const hash = createHash('sha256');
    handle = await open(location, 'r');

    const headLength = Math.min(metadata.size, CONTENT_PROBE_BYTES);
    const head = Buffer.alloc(headLength);

    if (headLength > 0) {
      const { bytesRead } = await handle.read(head, 0, headLength, 0);
      hash.update(head.subarray(0, bytesRead));
    }

    if (metadata.size > CONTENT_PROBE_BYTES) {
      const tailLength = Math.min(metadata.size - CONTENT_PROBE_BYTES, CONTENT_PROBE_BYTES);
      const tail = Buffer.alloc(tailLength);
      const start = Math.max(0, metadata.size - tailLength);
      const { bytesRead } = await handle.read(tail, 0, tailLength, start);
      hash.update(tail.subarray(0, bytesRead));
    }

    return {
      contentProbeHash: hash.digest('hex'),
      ctimeMs: metadata.ctimeMs,
      mtimeMs: metadata.mtimeMs,
      size: metadata.size,
    };
  } catch {
    return undefined;
  } finally {
    await handle?.close();
  }
}

function buildTypesKey(selection: ResolvedSecretTypeSelection): string {
  return selection.checkedTypes.join(',');
}

function buildEntryKey(handle: SessionHandle, typesKey: string): string {
  return JSON.stringify([handle.provider, handle.sessionId, handle.location, typesKey]);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isValidFingerprint(value: unknown): value is CacheLocationFingerprint {
  return (
    isRecord(value) &&
    typeof value.contentProbeHash === 'string' &&
    typeof value.ctimeMs === 'number' &&
    Number.isFinite(value.ctimeMs) &&
    typeof value.mtimeMs === 'number' &&
    Number.isFinite(value.mtimeMs) &&
    typeof value.size === 'number' &&
    Number.isFinite(value.size)
  );
}

function isValidFinding(value: unknown): value is ScanFinding {
  return (
    isRecord(value) &&
    typeof value.fingerprint === 'string' &&
    typeof value.preview === 'string' &&
    typeof value.type === 'string' &&
    (value.rawSample === undefined || typeof value.rawSample === 'string')
  );
}

function isValidEntry(value: unknown): value is CacheEntry {
  return (
    isRecord(value) &&
    Array.isArray(value.findings) &&
    value.findings.every((finding) => isValidFinding(finding)) &&
    isValidFingerprint(value.fingerprint) &&
    typeof value.hasChanges === 'boolean'
  );
}

function sanitizeFindings(findings: ScanFinding[]): ScanFinding[] {
  return findings.map((finding) => ({
    fingerprint: finding.fingerprint,
    preview: finding.preview,
    type: finding.type,
  }));
}

export class ScanCache {
  private readonly entries = new Map<string, CacheEntry>();
  private dirty = false;
  private readonly typesKey: string;

  private constructor(selection: ResolvedSecretTypeSelection) {
    this.typesKey = buildTypesKey(selection);
  }

  static async load(selection: ResolvedSecretTypeSelection): Promise<ScanCache> {
    const cache = new ScanCache(selection);

    const cachePath = getScanCachePath();

    if (process.env.AGENTWARDEN_DISABLE_SCAN_CACHE === '1' || !(await pathExists(cachePath))) {
      return cache;
    }

    try {
      const parsed = JSON.parse(await readFile(cachePath, 'utf8')) as unknown;

      if (!isRecord(parsed) || parsed.version !== SCAN_CACHE_VERSION || !isRecord(parsed.entries)) {
        return cache;
      }

      Object.entries(parsed.entries).forEach(([key, entry]) => {
        if (isValidEntry(entry)) {
          cache.entries.set(key, entry);
        }
      });
    } catch {
      return cache;
    }

    return cache;
  }

  async get(handle: SessionHandle): Promise<CachedSessionAnalysis | undefined> {
    if (process.env.AGENTWARDEN_DISABLE_SCAN_CACHE === '1') {
      return undefined;
    }

    const key = buildEntryKey(handle, this.typesKey);
    const entry = this.entries.get(key);

    if (entry === undefined) {
      return undefined;
    }

    const fingerprint = await getLocationFingerprint(handle.location);

    if (
      fingerprint === undefined ||
      fingerprint.contentProbeHash !== entry.fingerprint.contentProbeHash ||
      fingerprint.ctimeMs !== entry.fingerprint.ctimeMs ||
      fingerprint.mtimeMs !== entry.fingerprint.mtimeMs ||
      fingerprint.size !== entry.fingerprint.size
    ) {
      this.entries.delete(key);
      this.dirty = true;
      return undefined;
    }

    return {
      findings: entry.findings,
      hasChanges: entry.hasChanges,
    };
  }

  async set(handle: SessionHandle, value: CachedSessionAnalysis): Promise<void> {
    if (process.env.AGENTWARDEN_DISABLE_SCAN_CACHE === '1') {
      return;
    }

    const fingerprint = await getLocationFingerprint(handle.location);

    if (fingerprint === undefined) {
      return;
    }

    this.entries.set(buildEntryKey(handle, this.typesKey), {
      findings: sanitizeFindings(value.findings),
      fingerprint,
      hasChanges: value.hasChanges,
    });
    this.dirty = true;
  }

  async persist(): Promise<void> {
    if (!this.dirty || process.env.AGENTWARDEN_DISABLE_SCAN_CACHE === '1') {
      return;
    }

    const cachePath = getScanCachePath();
    const directory = path.dirname(cachePath);
    await ensurePrivateDir(directory);
    await writePrivateFile(
      cachePath,
      `${JSON.stringify({ version: SCAN_CACHE_VERSION, entries: Object.fromEntries(this.entries) })}\n`,
    );
    this.dirty = false;
  }
}
