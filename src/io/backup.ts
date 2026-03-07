import { copyFile, stat, writeFile } from 'node:fs/promises';
import path from 'node:path';
import type { SessionArtifact } from '../providers/types.js';
import { buildUtcTimestamp, ensureDir, expandHomeDir, toBackupRelativePath } from './paths.js';
import { createSqliteBackup } from './sqlite.js';

export interface BackupManifestEntry {
  sessionId: string;
  provider: string;
  originalPath: string;
  backupPath: string;
  kind: 'file' | 'sqlite';
}

export interface BackupResult {
  root: string;
  manifestPath: string;
  entries: BackupManifestEntry[];
}

function defaultBackupRoot(): string {
  return expandHomeDir(`~/.agentwarden/backups/${buildUtcTimestamp()}-mask_secrets`);
}

async function backupTarget(target: { kind: 'file' | 'sqlite'; path: string }, destinationPath: string): Promise<void> {
  await ensureDir(path.dirname(destinationPath));

  if (target.kind === 'sqlite') {
    await createSqliteBackup(target.path, destinationPath);
    return;
  }

  await copyFile(target.path, destinationPath);
}

export async function createBackups(artifacts: SessionArtifact[], backupRoot = defaultBackupRoot()): Promise<BackupResult> {
  try {
    await ensureDir(backupRoot);

    const entries: BackupManifestEntry[] = [];
    const seenTargets = new Map<string, string>();

    for (const artifact of artifacts) {
      for (const target of artifact.backupTargets) {
        const targetKey = `${target.kind}:${target.path}`;
        let backupPath = seenTargets.get(targetKey);

        if (backupPath === undefined) {
          backupPath = path.join(backupRoot, toBackupRelativePath(target.path));
          await backupTarget(target, backupPath);
          seenTargets.set(targetKey, backupPath);
        }

        entries.push({
          sessionId: artifact.handle.sessionId,
          provider: artifact.handle.provider,
          originalPath: target.path,
          backupPath,
          kind: target.kind,
        });
      }
    }

    const manifestPath = path.join(backupRoot, 'manifest.json');
    await writeFile(
      manifestPath,
      `${JSON.stringify({ createdAt: new Date().toISOString(), root: backupRoot, entries }, null, 2)}\n`,
      'utf8',
    );

    return { root: backupRoot, manifestPath, entries };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    const details = await describeBackupRootFailure(backupRoot);
    throw new Error(`Unable to create backups at ${backupRoot}: ${message}${details === '' ? '' : ` (${details})`}`);
  }
}

async function describeBackupRootFailure(backupRoot: string): Promise<string> {
  const parentDir = path.dirname(backupRoot);

  try {
    const info = await stat(parentDir);

    if (!info.isDirectory()) {
      return `parent path is not a directory: ${parentDir}`;
    }

    return `check write permissions for ${parentDir}`;
  } catch {
    return `check write permissions for ${parentDir}`;
  }
}
