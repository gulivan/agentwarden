import { access, chmod, mkdir, writeFile } from 'node:fs/promises';
import { constants } from 'node:fs';
import { homedir } from 'node:os';
import path from 'node:path';

export const PRIVATE_DIRECTORY_MODE = 0o700;
export const PRIVATE_FILE_MODE = 0o600;

export function expandHomeDir(inputPath: string): string {
  if (inputPath === '~') {
    return homedir();
  }

  if (inputPath.startsWith('~/')) {
    return path.join(homedir(), inputPath.slice(2));
  }

  return inputPath;
}

export async function pathExists(targetPath: string): Promise<boolean> {
  try {
    await access(targetPath, constants.F_OK);
    return true;
  } catch {
    return false;
  }
}

export async function ensureDir(targetPath: string): Promise<void> {
  await mkdir(targetPath, { recursive: true });
}

export async function ensurePrivateDir(targetPath: string): Promise<void> {
  await mkdir(targetPath, { recursive: true, mode: PRIVATE_DIRECTORY_MODE });
  await chmod(targetPath, PRIVATE_DIRECTORY_MODE);
}

export async function writePrivateFile(filePath: string, content: string): Promise<void> {
  await writeFile(filePath, content, { encoding: 'utf8', mode: PRIVATE_FILE_MODE });
  await chmod(filePath, PRIVATE_FILE_MODE);
}

export async function chmodPrivateFile(filePath: string): Promise<void> {
  await chmod(filePath, PRIVATE_FILE_MODE);
}

export function buildUtcTimestamp(): string {
  return new Date().toISOString().replace(/[-:]/g, '').replace(/\.\d{3}Z$/, 'Z');
}

export function isSafePathSegment(value: string): boolean {
  return value.length > 0 && value !== '.' && value !== '..' && !/[\\/\0]/.test(value);
}

export function joinSafePathSegment(root: string, segment: string): string | undefined {
  return isSafePathSegment(segment) ? path.join(root, segment) : undefined;
}

export function isPathInsideDirectory(parentDir: string, childPath: string): boolean {
  const relative = path.relative(parentDir, childPath);
  return relative === '' || (!relative.startsWith('..') && !path.isAbsolute(relative));
}

export function resolvePathInsideDirectory(parentDir: string, candidatePath: string): string | undefined {
  const resolvedParentDir = path.resolve(parentDir);
  const resolvedCandidatePath = path.resolve(parentDir, candidatePath);
  return isPathInsideDirectory(resolvedParentDir, resolvedCandidatePath) ? resolvedCandidatePath : undefined;
}

export function toBackupRelativePath(originalPath: string): string {
  if (!path.isAbsolute(originalPath)) {
    throw new Error(`Backup target must be an absolute path: ${originalPath}`);
  }

  if (originalPath.includes('\0')) {
    throw new Error('Backup target path contains a null byte');
  }

  const normalized = path.normalize(originalPath);
  const root = path.parse(normalized).root;
  const relativePath = path.relative(root, normalized);
  const segments = relativePath.split(/[\\/]+/).filter((segment) => segment.length > 0);

  if (segments.some((segment) => segment === '.' || segment === '..')) {
    throw new Error(`Backup target escapes its root: ${originalPath}`);
  }

  if (/^[A-Za-z]:[\\/]*$/.test(root)) {
    segments.unshift(root[0] ?? 'drive');
  }

  if (segments.length === 0) {
    throw new Error(`Backup target must not point to a filesystem root: ${originalPath}`);
  }

  return path.join(...segments);
}
