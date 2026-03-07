import { unlink } from 'node:fs/promises';
import path from 'node:path';
import { writeJsonFile } from '../io/json.js';
import { expandHomeDir, pathExists } from '../io/paths.js';
import { isSqliteLockedError, openSqliteDatabase } from '../io/sqlite.js';
import { collectStringFields, listFilesRecursive } from './helpers.js';
import type {
  PersistResult,
  ProviderDiscoveryResult,
  ProviderReader,
  ProviderNotice,
  SessionArtifact,
  SessionHandle,
  StringFieldRef,
} from './types.js';

interface SqliteRowState {
  id: number | string;
  parsed: unknown;
  tracker: { changed: boolean };
}

interface JsonFileState {
  filePath: string;
  parsed: unknown;
  tracker: { changed: boolean };
}

interface OpenCodeStorageSessionRow {
  session: SessionHandle;
  updatedAt: number;
}

interface OpenCodeSource {
  kind: 'sqlite' | 'storage';
  databasePath?: string;
  storageRoot?: string;
}

function getOpenCodeRoot(): string {
  if (process.env.CCBOX_OPENCODE_ROOT !== undefined && process.env.CCBOX_OPENCODE_ROOT.length > 0) {
    return expandHomeDir(process.env.CCBOX_OPENCODE_ROOT);
  }

  if (process.env.XDG_DATA_HOME !== undefined && process.env.XDG_DATA_HOME.length > 0) {
    return path.join(expandHomeDir(process.env.XDG_DATA_HOME), 'opencode');
  }

  return expandHomeDir('~/.local/share/opencode');
}

function getOpenCodeDatabasePath(): string {
  if (process.env.CCBOX_OPENCODE_DB_PATH !== undefined && process.env.CCBOX_OPENCODE_DB_PATH.length > 0) {
    return expandHomeDir(process.env.CCBOX_OPENCODE_DB_PATH);
  }

  return path.join(getOpenCodeRoot(), 'opencode.db');
}

function getOpenCodeStorageRoot(): string {
  if (process.env.CCBOX_OPENCODE_STORAGE_ROOT !== undefined && process.env.CCBOX_OPENCODE_STORAGE_ROOT.length > 0) {
    return expandHomeDir(process.env.CCBOX_OPENCODE_STORAGE_ROOT);
  }

  return path.join(getOpenCodeRoot(), 'storage');
}

function getOpenCodeCachePath(sessionId: string): string {
  return expandHomeDir(`~/.ccbox/opencode/sessions/${sessionId}.jsonl`);
}

function normalizeString(value: unknown): string | undefined {
  return typeof value === 'string' && value.length > 0 ? value : undefined;
}

function toRecord(value: unknown): Record<string, unknown> | undefined {
  return typeof value === 'object' && value !== null && !Array.isArray(value) ? (value as Record<string, unknown>) : undefined;
}

function toTimestamp(value: unknown): number {
  return typeof value === 'number' && Number.isFinite(value) ? value : 0;
}

function getStorageRootFromSessionPath(sessionPath: string): string {
  return path.dirname(path.dirname(path.dirname(sessionPath)));
}

async function discoverOpenCodeSource(): Promise<OpenCodeSource | undefined> {
  const storageRoot = getOpenCodeStorageRoot();
  const sessionRoot = path.join(storageRoot, 'session');

  if (await pathExists(sessionRoot)) {
    return { kind: 'storage', storageRoot };
  }

  const databasePath = getOpenCodeDatabasePath();

  if (await pathExists(databasePath)) {
    return { kind: 'sqlite', databasePath };
  }

  return undefined;
}

async function buildOpenCodeProjectWorktreeMap(projectRoot: string): Promise<Map<string, string>> {
  const worktreeByProjectId = new Map<string, string>();

  if (!(await pathExists(projectRoot))) {
    return worktreeByProjectId;
  }

  let projectFiles: string[] = [];

  try {
    projectFiles = await listFilesRecursive(projectRoot, '.json');
  } catch {
    return worktreeByProjectId;
  }

  for (const filePath of projectFiles) {
    try {
      const projectRecord = toRecord(await Bun.file(filePath).json());
      const projectId = normalizeString(projectRecord?.id);
      const worktree = normalizeString(projectRecord?.worktree);

      if (projectId !== undefined && worktree !== undefined) {
        worktreeByProjectId.set(projectId, worktree);
      }
    } catch {
      // ignore invalid project metadata during discovery; sessions can still be loaded
    }
  }

  return worktreeByProjectId;
}

async function discoverStorageSessions(storageRoot: string): Promise<ProviderDiscoveryResult> {
  const sessionRoot = path.join(storageRoot, 'session');

  if (!(await pathExists(sessionRoot))) {
    return {
      sessions: [],
      warnings: [{ provider: 'opencode', level: 'warning', message: `Missing OpenCode storage directory: ${sessionRoot}` }],
      errors: [],
    };
  }

  const warnings: ProviderDiscoveryResult['warnings'] = [];
  const worktreeByProjectId = await buildOpenCodeProjectWorktreeMap(path.join(storageRoot, 'project'));
  const sessionFiles = await listFilesRecursive(sessionRoot, '.json');
  const discovered: OpenCodeStorageSessionRow[] = [];

  for (const filePath of sessionFiles) {
    try {
      const sessionRecord = toRecord(await Bun.file(filePath).json());

      if (sessionRecord === undefined) {
        throw new Error('session payload is not an object');
      }

      const sessionId = normalizeString(sessionRecord.id) ?? path.basename(filePath, '.json');
      const projectId = normalizeString(sessionRecord.projectID) ?? normalizeString(sessionRecord.projectId) ?? '';
      const timeRecord = toRecord(sessionRecord.time);
      const updatedAt = toTimestamp(timeRecord?.updated) || toTimestamp(timeRecord?.created);

      discovered.push({
        updatedAt,
        session: {
          provider: 'opencode',
          sessionId,
          location: filePath,
          title: normalizeString(sessionRecord.title),
          metadata: {
            format: 'storage',
            storageRoot,
            projectId,
            directory: normalizeString(sessionRecord.directory) ?? '',
            worktree: worktreeByProjectId.get(projectId) ?? '',
          },
        },
      });
    } catch (error) {
      warnings.push({
        provider: 'opencode',
        level: 'warning',
        message: `Skipping unreadable OpenCode session ${filePath}: ${error instanceof Error ? error.message : String(error)}`,
      });
    }
  }

  discovered.sort((left, right) => {
    if (left.updatedAt !== right.updatedAt) {
      return right.updatedAt - left.updatedAt;
    }

    return right.session.sessionId.localeCompare(left.session.sessionId);
  });

  return { sessions: discovered.map((entry) => entry.session), warnings, errors: [] };
}

async function discoverSqliteSessions(databasePath: string): Promise<ProviderDiscoveryResult> {
  const warnings: ProviderDiscoveryResult['warnings'] = [];

  try {
    const database = openSqliteDatabase(databasePath, { readonly: true, create: false, busyTimeoutMs: 250 });

    try {
      const rows = database
        .query(
          'SELECT s.id, s.title, s.directory, s.time_created, s.time_updated, p.worktree FROM session s JOIN project p ON p.id = s.project_id WHERE s.time_archived IS NULL ORDER BY s.time_updated DESC, s.id DESC',
        )
        .all() as Array<Record<string, unknown>>;

      return {
        sessions: rows.map((row) => ({
          provider: 'opencode',
          sessionId: String(row.id),
          location: databasePath,
          title: normalizeString(row.title),
          metadata: {
            format: 'sqlite',
            directory: normalizeString(row.directory) ?? '',
            worktree: normalizeString(row.worktree) ?? '',
          },
        })),
        warnings,
        errors: [],
      };
    } finally {
      database.close();
    }
  } catch (error) {
    const lockedMessage = isSqliteLockedError(error)
      ? 'OpenCode database is locked; close OpenCode and retry.'
      : `Unable to read OpenCode database: ${error instanceof Error ? error.message : String(error)}`;

    return {
      sessions: [],
      warnings: [{ provider: 'opencode', level: 'warning', message: lockedMessage }],
      errors: [],
    };
  }
}

async function loadStorageSession(handle: SessionHandle): Promise<SessionArtifact> {
  const sessionPath = handle.location;
  const storageRoot = handle.metadata?.storageRoot ?? getStorageRootFromSessionPath(sessionPath);
  const warnings: ProviderNotice[] = [];
  const fields: StringFieldRef[] = [];
  const backupTargets = new Set<string>([sessionPath]);

  const sessionParsed = await Bun.file(sessionPath).json();
  const sessionTracker = { changed: false };

  fields.push(
    ...collectStringFields({
      value: sessionParsed,
      sourceLabel: sessionPath,
      basePath: 'session',
      tracker: sessionTracker,
    }),
  );

  const messageStates: JsonFileState[] = [];
  const partStates: JsonFileState[] = [];
  const messageRoot = path.join(storageRoot, 'message', handle.sessionId);

  if (await pathExists(messageRoot)) {
    const messageFiles = (await listFilesRecursive(messageRoot, '.json')).sort((left, right) => left.localeCompare(right));

    for (const filePath of messageFiles) {
      backupTargets.add(filePath);

      try {
        const parsed = await Bun.file(filePath).json();
        const tracker = { changed: false };
        messageStates.push({ filePath, parsed, tracker });
        fields.push(
          ...collectStringFields({
            value: parsed,
            sourceLabel: filePath,
            basePath: 'message',
            tracker,
          }),
        );
      } catch {
        warnings.push({
          provider: 'opencode',
          level: 'warning',
          sessionId: handle.sessionId,
          message: `Skipping malformed message file ${filePath}`,
        });
      }
    }
  }

  for (const messageState of messageStates) {
    const messageRecord = toRecord(messageState.parsed);
    const messageId = normalizeString(messageRecord?.id) ?? path.basename(messageState.filePath, '.json');
    const partRoot = path.join(storageRoot, 'part', messageId);

    if (!(await pathExists(partRoot))) {
      continue;
    }

    const partFiles = (await listFilesRecursive(partRoot, '.json')).sort((left, right) => left.localeCompare(right));

    for (const filePath of partFiles) {
      backupTargets.add(filePath);

      try {
        const parsed = await Bun.file(filePath).json();
        const tracker = { changed: false };
        partStates.push({ filePath, parsed, tracker });
        fields.push(
          ...collectStringFields({
            value: parsed,
            sourceLabel: filePath,
            basePath: 'part',
            tracker,
          }),
        );
      } catch {
        warnings.push({
          provider: 'opencode',
          level: 'warning',
          sessionId: handle.sessionId,
          message: `Skipping malformed part file ${filePath}`,
        });
      }
    }
  }

  return {
    handle,
    fields,
    warnings,
    backupTargets: [...backupTargets].map((filePath) => ({ kind: 'file' as const, path: filePath })),
    async writeChanges(): Promise<PersistResult> {
      const nestedContentChanged =
        messageStates.some((state) => state.tracker.changed) || partStates.some((state) => state.tracker.changed);

      if (nestedContentChanged) {
        const sessionRecord = toRecord(sessionParsed);
        const timeRecord = toRecord(sessionRecord?.time);

        if (timeRecord !== undefined) {
          timeRecord.updated = Date.now();
          sessionTracker.changed = true;
        }
      }

      const changedStates = [
        ...(sessionTracker.changed ? [{ filePath: sessionPath, parsed: sessionParsed }] : []),
        ...messageStates.filter((state) => state.tracker.changed).map((state) => ({ filePath: state.filePath, parsed: state.parsed })),
        ...partStates.filter((state) => state.tracker.changed).map((state) => ({ filePath: state.filePath, parsed: state.parsed })),
      ];

      if (changedStates.length === 0) {
        return { writes: [], warnings: [] };
      }

      for (const state of changedStates) {
        await writeJsonFile(state.filePath, state.parsed);
      }

      return { writes: changedStates.map((state) => state.filePath), warnings: [] };
    },
  };
}

async function loadSqliteSession(handle: SessionHandle): Promise<SessionArtifact> {
  const databasePath = handle.location;
  const database = openSqliteDatabase(databasePath, { readonly: true, create: false, busyTimeoutMs: 250 });
  const warnings: ProviderNotice[] = [];

  try {
    const sessionRow = database
      .query('SELECT s.id, s.title, s.directory FROM session s WHERE s.id = ?1 LIMIT 1')
      .get(handle.sessionId) as Record<string, unknown> | null;
    const messageRows = database
      .query('SELECT id, data FROM message WHERE session_id = ?1 ORDER BY time_created ASC, id ASC')
      .all(handle.sessionId) as Array<Record<string, unknown>>;
    const partRows = database
      .query('SELECT id, message_id, data FROM part WHERE session_id = ?1 ORDER BY time_created ASC, message_id ASC, id ASC')
      .all(handle.sessionId) as Array<Record<string, unknown>>;

    const fields: StringFieldRef[] = [];
    const sessionTracker = { changed: false };
    const sessionState = {
      title: normalizeString(sessionRow?.title) ?? '',
      directory: normalizeString(sessionRow?.directory) ?? '',
    };

    fields.push(
      ...collectStringFields({
        value: sessionState,
        sourceLabel: `${databasePath}:session:${handle.sessionId}`,
        basePath: 'session',
        tracker: sessionTracker,
      }),
    );

    const parsedMessageRows: SqliteRowState[] = [];
    const parsedPartRows: SqliteRowState[] = [];

    for (const row of messageRows) {
      const rawData = row.data;

      if (typeof rawData !== 'string') {
        continue;
      }

      try {
        const parsed = JSON.parse(rawData) as unknown;
        const tracker = { changed: false };
        parsedMessageRows.push({ id: typeof row.id === 'number' || typeof row.id === 'string' ? row.id : String(row.id ?? ''), parsed, tracker });
        fields.push(
          ...collectStringFields({
            value: parsed,
            sourceLabel: `${databasePath}:message:${String(row.id)}`,
            basePath: 'message.data',
            tracker,
          }),
        );
      } catch {
        warnings.push({
          provider: 'opencode',
          level: 'warning',
          sessionId: handle.sessionId,
          message: `Skipping malformed message row ${String(row.id)}`,
        });
      }
    }

    for (const row of partRows) {
      const rawData = row.data;

      if (typeof rawData !== 'string') {
        continue;
      }

      try {
        const parsed = JSON.parse(rawData) as unknown;
        const tracker = { changed: false };
        parsedPartRows.push({ id: typeof row.id === 'number' || typeof row.id === 'string' ? row.id : String(row.id ?? ''), parsed, tracker });
        fields.push(
          ...collectStringFields({
            value: parsed,
            sourceLabel: `${databasePath}:part:${String(row.id)}`,
            basePath: 'part.data',
            tracker,
          }),
        );
      } catch {
        warnings.push({
          provider: 'opencode',
          level: 'warning',
          sessionId: handle.sessionId,
          message: `Skipping malformed part row ${String(row.id)}`,
        });
      }
    }

    return {
      handle,
      fields,
      warnings,
      backupTargets: [{ kind: 'sqlite', path: databasePath }],
      async writeChanges(): Promise<PersistResult> {
        const hasChanges =
          sessionTracker.changed ||
          parsedMessageRows.some((row) => row.tracker.changed) ||
          parsedPartRows.some((row) => row.tracker.changed);

        if (!hasChanges) {
          return { writes: [], warnings: [] };
        }

        const writeDatabase = openSqliteDatabase(databasePath, { readonly: false, create: false, busyTimeoutMs: 500 });

        try {
          writeDatabase.exec('BEGIN IMMEDIATE');

          if (sessionTracker.changed) {
            writeDatabase
              .query(
                "UPDATE session SET title = ?1, directory = ?2, time_updated = CAST(unixepoch('now') * 1000 AS INTEGER) WHERE id = ?3",
              )
              .run(sessionState.title, sessionState.directory, handle.sessionId);
          }

          for (const row of parsedMessageRows) {
            if (!row.tracker.changed) {
              continue;
            }

            writeDatabase
              .query('UPDATE message SET data = ?1 WHERE id = ?2')
              .run(JSON.stringify(row.parsed), row.id);
          }

          for (const row of parsedPartRows) {
            if (!row.tracker.changed) {
              continue;
            }

            writeDatabase
              .query('UPDATE part SET data = ?1 WHERE id = ?2')
              .run(JSON.stringify(row.parsed), row.id);
          }

          if (!sessionTracker.changed) {
            writeDatabase.query("UPDATE session SET time_updated = CAST(unixepoch('now') * 1000 AS INTEGER) WHERE id = ?1").run(handle.sessionId);
          }

          writeDatabase.exec('COMMIT');
        } catch (error) {
          try {
            writeDatabase.exec('ROLLBACK');
          } catch {
            // ignore rollback errors
          }

          const message = isSqliteLockedError(error)
            ? 'OpenCode database is locked; close OpenCode and retry.'
            : error instanceof Error
              ? error.message
              : String(error);
          throw new Error(message);
        } finally {
          writeDatabase.close();
        }

        try {
          await unlink(getOpenCodeCachePath(handle.sessionId));
        } catch {
          // best effort cache invalidation
        }

        return { writes: [databasePath], warnings: [] };
      },
    };
  } finally {
    database.close();
  }
}

export const opencodeProvider: ProviderReader = {
  provider: 'opencode',
  async discoverSessions(): Promise<ProviderDiscoveryResult> {
    const source = await discoverOpenCodeSource();

    if (source?.kind === 'storage' && source.storageRoot !== undefined) {
      return discoverStorageSessions(source.storageRoot);
    }

    if (source?.kind === 'sqlite' && source.databasePath !== undefined) {
      return discoverSqliteSessions(source.databasePath);
    }

    return {
      sessions: [],
      warnings: [
        {
          provider: 'opencode',
          level: 'warning',
          message: `Missing OpenCode storage directory: ${path.join(getOpenCodeStorageRoot(), 'session')}`,
        },
      ],
      errors: [],
    };
  },
  async loadSession(handle: SessionHandle): Promise<SessionArtifact> {
    if (handle.metadata?.format === 'storage' || handle.location.endsWith('.json')) {
      return loadStorageSession(handle);
    }

    return loadSqliteSession(handle);
  },
};
