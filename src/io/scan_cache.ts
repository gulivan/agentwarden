import { readFile } from 'node:fs/promises';
import { stat } from 'node:fs/promises';
import path from 'node:path';
import { ensurePrivateDir, expandHomeDir, pathExists, writePrivateFile } from './paths.js';
import type { SessionHandle } from '../providers/types.js';
import type { ResolvedSecretTypeSelection } from '../secrets/options.js';
import type { ScanFinding } from '../secrets/plan.js';

const SCAN_CACHE_VERSION = 2;

function getScanCachePath(): string {
  return expandHomeDir(process.env.AGENTWARDEN_SCAN_CACHE_PATH ?? '~/.agentwarden/cache/scan-results-v2.json');
}

interface CacheLocationFingerprint {
  mtimeMs: number;
  size: number;
}

interface CacheEntry {
  findings: ScanFinding[];
  fingerprint: CacheLocationFingerprint;
  hasChanges: boolean;
  location: string;
  provider: SessionHandle['provider'];
  sessionId: string;
  typesKey: string;
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
  try {
    const metadata = await stat(location);
    return { mtimeMs: metadata.mtimeMs, size: metadata.size };
  } catch {
    return undefined;
  }
}

function buildTypesKey(selection: ResolvedSecretTypeSelection): string {
  return selection.checkedTypes.join(',');
}

function buildEntryKey(handle: SessionHandle, typesKey: string): string {
  return `${handle.provider}:${handle.sessionId}:${handle.location}:${typesKey}`;
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
      const parsed = JSON.parse(await readFile(cachePath, 'utf8')) as CacheFile;

      if (parsed.version !== SCAN_CACHE_VERSION) {
        return cache;
      }

      Object.entries(parsed.entries).forEach(([key, entry]) => {
        cache.entries.set(key, entry);
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
      fingerprint.mtimeMs !== entry.fingerprint.mtimeMs ||
      fingerprint.size !== entry.fingerprint.size ||
      entry.provider !== handle.provider ||
      entry.sessionId !== handle.sessionId ||
      entry.location !== handle.location ||
      entry.typesKey !== this.typesKey
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
      findings: value.findings,
      fingerprint,
      hasChanges: value.hasChanges,
      location: handle.location,
      provider: handle.provider,
      sessionId: handle.sessionId,
      typesKey: this.typesKey,
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
