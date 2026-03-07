import { readdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import { expandHomeDir, pathExists } from '../io/paths.js';
import { createJsonlArtifact } from './helpers.js';
import type { ProviderDiscoveryResult, ProviderReader, SessionHandle } from './types.js';

interface ClaudeIndexEntry {
  sessionId: string;
  title?: string;
  fullPath?: string;
}

function toClaudeIndexEntries(value: unknown): ClaudeIndexEntry[] {
  const rawEntries = Array.isArray(value)
    ? value
    : typeof value === 'object' && value !== null && Array.isArray((value as Record<string, unknown>).sessions)
      ? ((value as Record<string, unknown>).sessions as unknown[])
      : [];

  return rawEntries.flatMap((entry) => {
    if (typeof entry !== 'object' || entry === null) {
      return [];
    }

    const record = entry as Record<string, unknown>;
    const sessionId = record.sessionId ?? record.id;

    if (typeof sessionId !== 'string' || sessionId.length === 0) {
      return [];
    }

    const titleCandidate = record.summary ?? record.firstPrompt ?? record.title;
    return [
      {
        sessionId,
        title: typeof titleCandidate === 'string' ? titleCandidate : undefined,
        fullPath: typeof record.fullPath === 'string' ? record.fullPath : undefined,
      },
    ];
  });
}

export const claudeProvider: ProviderReader = {
  provider: 'claude',
  async discoverSessions(): Promise<ProviderDiscoveryResult> {
    const projectsRoot = expandHomeDir(process.env.CLAUDE_PROJECTS_DIR ?? '~/.claude/projects');

    if (!(await pathExists(projectsRoot))) {
      return {
        sessions: [],
        warnings: [{ provider: 'claude', level: 'warning', message: `Missing projects directory: ${projectsRoot}` }],
        errors: [],
      };
    }

    const sessions: SessionHandle[] = [];
    const warnings: ProviderDiscoveryResult['warnings'] = [];
    const projectEntries = await readdir(projectsRoot, { withFileTypes: true });

    for (const projectEntry of projectEntries) {
      if (!projectEntry.isDirectory()) {
        continue;
      }

      const projectPath = path.join(projectsRoot, projectEntry.name);
      const hintMap = new Map<string, ClaudeIndexEntry>();
      const indexPath = path.join(projectPath, 'sessions-index.json');

      if (await pathExists(indexPath)) {
        try {
          const indexValue = JSON.parse(await readFile(indexPath, 'utf8')) as unknown;
          toClaudeIndexEntries(indexValue).forEach((entry) => hintMap.set(entry.sessionId, entry));
        } catch (error) {
          warnings.push({
            provider: 'claude',
            level: 'warning',
            message: `Ignoring invalid index ${indexPath}: ${error instanceof Error ? error.message : String(error)}`,
          });
        }
      }

      const siblingEntries = await readdir(projectPath, { withFileTypes: true });
      const discoveredPaths = new Set<string>();

      for (const siblingEntry of siblingEntries) {
        if (!siblingEntry.isFile() || !siblingEntry.name.endsWith('.jsonl')) {
          continue;
        }

        const filePath = path.join(projectPath, siblingEntry.name);
        discoveredPaths.add(filePath);
        const sessionId = path.basename(siblingEntry.name, '.jsonl');
        const hint = hintMap.get(sessionId);

        sessions.push({
          provider: 'claude',
          sessionId,
          location: filePath,
          title: hint?.title,
        });
      }

      for (const hint of hintMap.values()) {
        if (hint.fullPath === undefined || hint.fullPath.length === 0) {
          continue;
        }

        const filePath = path.isAbsolute(hint.fullPath) ? hint.fullPath : path.join(projectPath, hint.fullPath);

        if (discoveredPaths.has(filePath) || !(await pathExists(filePath))) {
          continue;
        }

        discoveredPaths.add(filePath);
        sessions.push({
          provider: 'claude',
          sessionId: hint.sessionId,
          location: filePath,
          title: hint.title,
        });
      }
    }

    return { sessions, warnings, errors: [] };
  },
  async loadSession(handle) {
    return createJsonlArtifact({ handle });
  },
};
