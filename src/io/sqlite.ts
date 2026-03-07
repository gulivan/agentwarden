import path from 'node:path';
import { Database } from 'bun:sqlite';
import { ensureDir } from './paths.js';

export interface OpenSqliteOptions {
  readonly?: boolean;
  create?: boolean;
  busyTimeoutMs?: number;
}

export function openSqliteDatabase(databasePath: string, options: OpenSqliteOptions = {}): Database {
  const readonly = options.readonly ?? false;
  const database = new Database(databasePath, {
    readonly,
    readwrite: !readonly,
    create: options.create ?? false,
  });

  if (options.busyTimeoutMs !== undefined) {
    database.exec(`PRAGMA busy_timeout = ${Math.max(0, Math.trunc(options.busyTimeoutMs))}`);
  }

  return database;
}

export async function createSqliteBackup(databasePath: string, backupPath: string): Promise<void> {
  await ensureDir(path.dirname(backupPath));
  const database = openSqliteDatabase(databasePath, { readonly: false, create: false, busyTimeoutMs: 500 });

  try {
    database.exec(`VACUUM INTO '${backupPath.replace(/'/g, "''")}'`);
  } finally {
    database.close();
  }
}

export function isSqliteLockedError(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error);
  return /locked|SQLITE_BUSY/i.test(message);
}
