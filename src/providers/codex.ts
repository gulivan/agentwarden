import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { expandHomeDir, pathExists } from '../io/paths.js';
import { createJsonlArtifact, listFilesRecursive } from './helpers.js';
import type { ProviderDiscoveryResult, ProviderReader, SessionHandle } from './types.js';

function sessionIdFromMeta(meta: Record<string, unknown>, filePath: string): string {
  const payload = typeof meta.payload === 'object' && meta.payload !== null ? (meta.payload as Record<string, unknown>) : undefined;
  const sessionId = payload?.id ?? meta.session_id ?? meta.sessionId ?? meta.id;
  return typeof sessionId === 'string' && sessionId.length > 0 ? sessionId : path.basename(filePath, '.jsonl');
}

export const codexProvider: ProviderReader = {
  provider: 'codex',
  async discoverSessions(): Promise<ProviderDiscoveryResult> {
    const sessionsRoot = expandHomeDir(process.env.CODEX_SESSIONS_DIR ?? '~/.codex/sessions');

    if (!(await pathExists(sessionsRoot))) {
      return {
        sessions: [],
        warnings: [{ provider: 'codex', level: 'warning', message: `Missing sessions directory: ${sessionsRoot}` }],
        errors: [],
      };
    }

    const files = await listFilesRecursive(sessionsRoot, '.jsonl');
    const sessions: SessionHandle[] = [];
    const warnings: ProviderDiscoveryResult['warnings'] = [];

    for (const filePath of files) {
      try {
        const content = await readFile(filePath, 'utf8');
        const firstLine = content.split(/\r?\n/, 1)[0]?.trim();

        if (firstLine === undefined || firstLine.length === 0) {
          continue;
        }

        const parsed = JSON.parse(firstLine) as Record<string, unknown>;

        if (parsed.type !== 'session_meta') {
          continue;
        }

        sessions.push({
          provider: 'codex',
          sessionId: sessionIdFromMeta(parsed, filePath),
          location: filePath,
          title: typeof parsed.title === 'string' ? parsed.title : undefined,
        });
      } catch (error) {
        warnings.push({
          provider: 'codex',
          level: 'warning',
          message: `Skipping unreadable session file ${filePath}: ${error instanceof Error ? error.message : String(error)}`,
        });
      }
    }

    return { sessions, warnings, errors: [] };
  },
  async loadSession(handle) {
    return createJsonlArtifact({ handle });
  },
};
