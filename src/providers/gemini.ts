import { readFile, readdir } from 'node:fs/promises';
import path from 'node:path';
import { expandHomeDir, pathExists } from '../io/paths.js';
import { createJsonArtifact } from './helpers.js';
import type { ProviderDiscoveryResult, ProviderReader, SessionHandle } from './types.js';

interface GeminiLogEntry {
  sessionId: string;
  message: string;
}

interface GeminiSessionHints {
  titleBySessionId: Map<string, string>;
  fullSessionIdByPrefix: Map<string, string>;
}

function sessionIdFromFile(filePath: string): string {
  const basename = path.basename(filePath, '.json');
  const suffix = basename.split('-').pop();
  return suffix === undefined || suffix.length === 0 ? basename : suffix;
}

function trimFirstLine(value: string): string | undefined {
  const firstLine = value
    .split(/\r?\n/, 1)[0]
    ?.trim();

  return firstLine === undefined || firstLine.length === 0 ? undefined : firstLine;
}

function parseGeminiLogs(value: unknown): GeminiLogEntry[] {
  if (!Array.isArray(value)) {
    return [];
  }

  return value.flatMap((entry) => {
    if (typeof entry !== 'object' || entry === null) {
      return [];
    }

    const record = entry as Record<string, unknown>;
    const sessionId = record.sessionId;
    const message = record.message;

    if (record.type !== 'user' || typeof sessionId !== 'string' || sessionId.length === 0 || typeof message !== 'string') {
      return [];
    }

    const title = trimFirstLine(message);
    return title === undefined ? [] : [{ sessionId, message: title }];
  });
}

function buildGeminiSessionHints(entries: GeminiLogEntry[]): GeminiSessionHints {
  const titleBySessionId = new Map<string, string>();
  const prefixCounts = new Map<string, number>();

  for (const entry of entries) {
    if (!titleBySessionId.has(entry.sessionId)) {
      titleBySessionId.set(entry.sessionId, entry.message);
    }

    const prefix = entry.sessionId.slice(0, 8);
    if (prefix.length > 0) {
      prefixCounts.set(prefix, (prefixCounts.get(prefix) ?? 0) + 1);
    }
  }

  const fullSessionIdByPrefix = new Map<string, string>();

  for (const entry of entries) {
    const prefix = entry.sessionId.slice(0, 8);

    if (prefix.length === 0 || prefixCounts.get(prefix) !== 1) {
      continue;
    }

    fullSessionIdByPrefix.set(prefix, entry.sessionId);
  }

  return { titleBySessionId, fullSessionIdByPrefix };
}

async function resolveSessionId(filePath: string, hints: GeminiSessionHints): Promise<{ sessionId: string; title?: string }> {
  const candidateSessionId = sessionIdFromFile(filePath);
  const hintedSessionId = hints.fullSessionIdByPrefix.get(candidateSessionId) ?? candidateSessionId;

  try {
    const parsed = JSON.parse(await readFile(filePath, 'utf8')) as unknown;

    if (typeof parsed === 'object' && parsed !== null) {
      const topLevelSessionId = (parsed as Record<string, unknown>).sessionId;
      if (typeof topLevelSessionId === 'string' && topLevelSessionId.length > 0) {
        return {
          sessionId: topLevelSessionId,
          title: hints.titleBySessionId.get(topLevelSessionId) ?? hints.titleBySessionId.get(hintedSessionId),
        };
      }
    }
  } catch {
    // leave the file for later artifact loading so scan/mask can surface parse errors consistently
  }

  return {
    sessionId: hintedSessionId,
    title: hints.titleBySessionId.get(hintedSessionId),
  };
}

export const geminiProvider: ProviderReader = {
  provider: 'gemini',
  async discoverSessions(): Promise<ProviderDiscoveryResult> {
    const geminiRoot = expandHomeDir(process.env.CCBOX_GEMINI_DIR ?? '~/.gemini');
    const tmpRoot = path.join(geminiRoot, 'tmp');

    if (!(await pathExists(tmpRoot))) {
      return {
        sessions: [],
        warnings: [{ provider: 'gemini', level: 'warning', message: `Missing Gemini tmp directory: ${tmpRoot}` }],
        errors: [],
      };
    }

    const sessions: SessionHandle[] = [];
    const warnings: ProviderDiscoveryResult['warnings'] = [];
    const workspaceEntries = await readdir(tmpRoot, { withFileTypes: true });

    for (const workspaceEntry of workspaceEntries) {
      if (!workspaceEntry.isDirectory() || !/^[0-9a-f]{64}$/i.test(workspaceEntry.name)) {
        continue;
      }

      const workspacePath = path.join(tmpRoot, workspaceEntry.name);
      const chatsPath = path.join(workspacePath, 'chats');
      const logsPath = path.join(workspacePath, 'logs.json');
      let hints: GeminiSessionHints = { titleBySessionId: new Map(), fullSessionIdByPrefix: new Map() };

      if (await pathExists(logsPath)) {
        try {
          hints = buildGeminiSessionHints(parseGeminiLogs(JSON.parse(await readFile(logsPath, 'utf8')) as unknown));
        } catch (error) {
          warnings.push({
            provider: 'gemini',
            level: 'warning',
            message: `Ignoring invalid Gemini logs ${logsPath}: ${error instanceof Error ? error.message : String(error)}`,
          });
        }
      }

      if (!(await pathExists(chatsPath))) {
        continue;
      }

      const chatEntries = await readdir(chatsPath, { withFileTypes: true });

      for (const chatEntry of chatEntries) {
        if (!chatEntry.isFile() || !/^session-.*\.json$/i.test(chatEntry.name)) {
          continue;
        }

        const filePath = path.join(chatsPath, chatEntry.name);
        const resolved = await resolveSessionId(filePath, hints);

        sessions.push({
          provider: 'gemini',
          sessionId: resolved.sessionId,
          location: filePath,
          title: resolved.title,
          metadata: { kind: 'chat' },
        });
      }
    }

    return { sessions, warnings, errors: [] };
  },
  async loadSession(handle) {
    return createJsonArtifact({ handle });
  },
};
