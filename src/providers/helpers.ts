import { readFile, readdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import type {
  BackupTarget,
  MaskPolicy,
  PersistResult,
  ProviderNotice,
  SessionArtifact,
  SessionHandle,
  StringFieldRef,
} from './types.js';

type PathSegment = string | number;

interface MutableTracker {
  changed: boolean;
}

interface CollectStringFieldOptions {
  value: unknown;
  sourceLabel: string;
  basePath: string;
  tracker: MutableTracker;
  policyOverride?: (contextKey: string | undefined, fieldPath: string) => MaskPolicy;
}

interface JsonlLine {
  raw: string;
  parsed?: unknown;
}

interface JsonlReadResult {
  lines: JsonlLine[];
  hadTrailingNewline: boolean;
  warnings: string[];
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function describePath(segments: PathSegment[]): string {
  let output = '';

  for (const segment of segments) {
    if (typeof segment === 'number') {
      output += `[${segment}]`;
      continue;
    }

    if (output.length === 0) {
      output = segment;
      continue;
    }

    output += `.${segment}`;
  }

  return output;
}

function inferMaskPolicy(contextKey: string | undefined, fieldPath: string): MaskPolicy {
  const normalizedKey = (contextKey ?? '').toLowerCase();
  const normalizedPath = fieldPath.toLowerCase();

  if (
    /(^|\.)(fullpath|projectpath|log_path|logpath|directory|worktree|filepath|path|cwd|location)(\.|$)/.test(
      normalizedPath,
    ) ||
    /^(fullpath|projectpath|log_path|logpath|directory|worktree|filepath|path|cwd|location)$/.test(normalizedKey)
  ) {
    return 'report_only';
  }

  if (/^(title|summary|firstprompt|subject|slug|name)$/.test(normalizedKey)) {
    return 'conditional';
  }

  return 'safe';
}

function collectStringFieldsInternal(
  currentValue: unknown,
  segments: PathSegment[],
  parent: Record<string, unknown> | unknown[] | undefined,
  parentKey: string | number | undefined,
  fields: StringFieldRef[],
  options: CollectStringFieldOptions,
): void {
  if (typeof currentValue === 'string') {
    const fieldPath = `${options.basePath}.${describePath(segments)}`;
    const contextKey = [...segments].reverse().find((segment) => typeof segment === 'string');
    const maskPolicy = options.policyOverride?.(contextKey, fieldPath) ?? inferMaskPolicy(contextKey, fieldPath);
    const fieldId = `${options.sourceLabel}:${fieldPath}`;

    fields.push({
      id: fieldId,
      path: fieldPath,
      sourceLabel: options.sourceLabel,
      value: currentValue,
      maskPolicy,
      contextKey,
      setValue(nextValue: string) {
        if (nextValue === this.value) {
          return;
        }

        if (Array.isArray(parent) && typeof parentKey === 'number') {
          parent[parentKey] = nextValue;
        } else if (!Array.isArray(parent) && parent !== undefined && typeof parentKey === 'string') {
          parent[parentKey] = nextValue;
        } else {
          return;
        }

        this.value = nextValue;
        options.tracker.changed = true;
      },
    });

    return;
  }

  if (Array.isArray(currentValue)) {
    currentValue.forEach((item, index) => {
      collectStringFieldsInternal(item, [...segments, index], currentValue, index, fields, options);
    });

    return;
  }

  if (isPlainObject(currentValue)) {
    for (const [key, nestedValue] of Object.entries(currentValue)) {
      collectStringFieldsInternal(nestedValue, [...segments, key], currentValue, key, fields, options);
    }
  }
}

export function collectStringFields(options: CollectStringFieldOptions): StringFieldRef[] {
  const fields: StringFieldRef[] = [];
  collectStringFieldsInternal(options.value, [], undefined, undefined, fields, options);
  return fields;
}

export async function listFilesRecursive(root: string, extension: string): Promise<string[]> {
  const results: string[] = [];
  const entries = await readdir(root, { withFileTypes: true });

  for (const entry of entries) {
    const entryPath = path.join(root, entry.name);

    if (entry.isDirectory()) {
      results.push(...(await listFilesRecursive(entryPath, extension)));
      continue;
    }

    if (entry.isFile() && entry.name.endsWith(extension)) {
      results.push(entryPath);
    }
  }

  return results;
}

export async function readJsonlDocument(filePath: string): Promise<JsonlReadResult> {
  const content = await readFile(filePath, 'utf8');
  const hadTrailingNewline = content.endsWith('\n');
  const lines = content.split(/\r?\n/);

  if (hadTrailingNewline) {
    lines.pop();
  }

  const warnings: string[] = [];
  const parsedLines: JsonlLine[] = lines.map((rawLine: string, index: number) => {
    if (rawLine.trim().length === 0) {
      return { raw: rawLine };
    }

    try {
      return { raw: rawLine, parsed: JSON.parse(rawLine) };
    } catch {
      warnings.push(`Skipping malformed JSONL line ${index + 1} in ${filePath}`);
      return { raw: rawLine };
    }
  });

  return { lines: parsedLines, hadTrailingNewline, warnings };
}

export async function writeJsonlDocument(filePath: string, result: JsonlReadResult): Promise<void> {
  const body = result.lines
    .map((line) => (line.parsed === undefined ? line.raw : JSON.stringify(line.parsed)))
    .join('\n');
  const output = result.hadTrailingNewline ? `${body}\n` : body;
  await writeFile(filePath, output, 'utf8');
}

export async function createJsonlArtifact(options: {
  handle: SessionHandle;
  providerWarnings?: ProviderNotice[];
  policyOverride?: (contextKey: string | undefined, fieldPath: string) => MaskPolicy;
}): Promise<SessionArtifact> {
  const tracker: MutableTracker = { changed: false };
  const document = await readJsonlDocument(options.handle.location);
  const warnings: ProviderNotice[] = [...(options.providerWarnings ?? [])];
  const fields: StringFieldRef[] = [];

  for (const warning of document.warnings) {
    warnings.push({ provider: options.handle.provider, level: 'warning', message: warning, sessionId: options.handle.sessionId });
  }

  document.lines.forEach((line, index) => {
    if (line.parsed === undefined) {
      return;
    }

    fields.push(
      ...collectStringFields({
        value: line.parsed,
        sourceLabel: `${options.handle.location}:${index + 1}`,
        basePath: `line[${index}]`,
        tracker,
        policyOverride: options.policyOverride,
      }),
    );
  });

  return {
    handle: options.handle,
    fields,
    warnings,
    backupTargets: [{ kind: 'file', path: options.handle.location }],
    async writeChanges(): Promise<PersistResult> {
      if (!tracker.changed) {
        return { writes: [], warnings: [] };
      }

      await writeJsonlDocument(options.handle.location, document);
      return { writes: [options.handle.location], warnings: [] };
    },
  };
}

export async function createJsonArtifact(options: {
  handle: SessionHandle;
  policyOverride?: (contextKey: string | undefined, fieldPath: string) => MaskPolicy;
}): Promise<SessionArtifact> {
  const tracker: MutableTracker = { changed: false };
  const content = await readFile(options.handle.location, 'utf8');
  const parsed = JSON.parse(content) as unknown;
  const fields = collectStringFields({
    value: parsed,
    sourceLabel: options.handle.location,
    basePath: 'root',
    tracker,
    policyOverride: options.policyOverride,
  });

  return {
    handle: options.handle,
    fields,
    warnings: [],
    backupTargets: [{ kind: 'file', path: options.handle.location }],
    async writeChanges(): Promise<PersistResult> {
      if (!tracker.changed) {
        return { writes: [], warnings: [] };
      }

      await writeFile(options.handle.location, `${JSON.stringify(parsed, null, 2)}\n`, 'utf8');
      return { writes: [options.handle.location], warnings: [] };
    },
  };
}
