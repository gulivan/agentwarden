import { afterEach, describe, expect, test } from 'bun:test';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { createBackups } from '../src/io/backup.js';
import { claudeProvider } from '../src/providers/claude.js';
import { opencodeProvider } from '../src/providers/opencode.js';
import type { SessionArtifact } from '../src/providers/types.js';

const tempDirs: string[] = [];

afterEach(async () => {
  await Promise.all(tempDirs.splice(0).map((directory) => rm(directory, { force: true, recursive: true })));
});

async function createTempDir(prefix: string): Promise<string> {
  const directory = await mkdtemp(path.join(tmpdir(), prefix));
  tempDirs.push(directory);
  return directory;
}

describe('backup safety', () => {
  test('rejects non-absolute backup targets', async () => {
    const artifact: SessionArtifact = {
      handle: {
        provider: 'codex',
        sessionId: 'session-1',
        location: '/tmp/session-1.jsonl',
      },
      fields: [],
      warnings: [],
      backupTargets: [{ kind: 'file', path: '../escape.jsonl' }],
      async writeChanges() {
        return { writes: [], warnings: [] };
      },
    };

    await expect(createBackups([artifact], path.join(await createTempDir('agentwarden-backups-'), 'backups'))).rejects.toThrow(
      'absolute path',
    );
  });
});

describe('OpenCode storage safety', () => {
  test('skips message roots derived from unsafe session ids', async () => {
    const storageRoot = await createTempDir('agentwarden-opencode-session-');
    const sessionRoot = path.join(storageRoot, 'session');
    const escapeRoot = path.join(storageRoot, 'escape');
    const sessionPath = path.join(sessionRoot, 'session.json');
    const leakedMessagePath = path.join(escapeRoot, 'message.json');

    await mkdir(sessionRoot, { recursive: true });
    await mkdir(escapeRoot, { recursive: true });
    await writeFile(sessionPath, JSON.stringify({ title: 'safe session' }));
    await writeFile(leakedMessagePath, JSON.stringify({ leaked: 'sk-ant-1234567890abcdef' }));

    const artifact = await opencodeProvider.loadSession({
      provider: 'opencode',
      sessionId: '../escape',
      location: sessionPath,
      metadata: { format: 'storage', storageRoot },
    });

    expect(artifact.warnings.some((warning) => warning.message.includes('session id is not a safe path segment'))).toBe(true);
    expect(artifact.fields.some((field) => field.sourceLabel === leakedMessagePath)).toBe(false);
  });

  test('skips part roots derived from unsafe message ids', async () => {
    const storageRoot = await createTempDir('agentwarden-opencode-message-');
    const sessionRoot = path.join(storageRoot, 'session');
    const messageRoot = path.join(storageRoot, 'message', 'session-1');
    const escapeRoot = path.join(storageRoot, 'escape');
    const sessionPath = path.join(sessionRoot, 'session.json');
    const messagePath = path.join(messageRoot, 'message.json');
    const leakedPartPath = path.join(escapeRoot, 'part.json');

    await mkdir(sessionRoot, { recursive: true });
    await mkdir(messageRoot, { recursive: true });
    await mkdir(escapeRoot, { recursive: true });
    await writeFile(sessionPath, JSON.stringify({ title: 'safe session' }));
    await writeFile(messagePath, JSON.stringify({ id: '../escape', text: 'safe message' }));
    await writeFile(leakedPartPath, JSON.stringify({ leaked: 'sk-ant-1234567890abcdef' }));

    const artifact = await opencodeProvider.loadSession({
      provider: 'opencode',
      sessionId: 'session-1',
      location: sessionPath,
      metadata: { format: 'storage', storageRoot },
    });

    expect(artifact.warnings.some((warning) => warning.message.includes('message id is not a safe path segment'))).toBe(true);
    expect(artifact.fields.some((field) => field.sourceLabel === leakedPartPath)).toBe(false);
  });
});

describe('Claude discovery safety', () => {
  test('ignores session index paths that escape the project directory', async () => {
    const projectsRoot = await createTempDir('agentwarden-claude-projects-');
    const projectPath = path.join(projectsRoot, 'project-a');
    const validSessionPath = path.join(projectPath, 'inside.jsonl');
    const outsideSessionPath = path.join(projectsRoot, 'outside.jsonl');
    const indexPath = path.join(projectPath, 'sessions-index.json');
    const previousProjectsDir = process.env.CLAUDE_PROJECTS_DIR;

    await mkdir(projectPath, { recursive: true });
    await writeFile(validSessionPath, '');
    await writeFile(outsideSessionPath, '');
    await writeFile(
      indexPath,
      JSON.stringify([
        { sessionId: 'inside', fullPath: 'inside.jsonl', title: 'inside' },
        { sessionId: 'outside', fullPath: '../outside.jsonl', title: 'outside' },
      ]),
    );

    process.env.CLAUDE_PROJECTS_DIR = projectsRoot;

    try {
      const discovery = await claudeProvider.discoverSessions();

      expect(discovery.sessions.some((session) => session.location === validSessionPath)).toBe(true);
      expect(discovery.sessions.some((session) => session.location === outsideSessionPath)).toBe(false);
      expect(discovery.warnings.some((warning) => warning.message.includes('Ignoring out-of-project session path'))).toBe(true);
    } finally {
      if (previousProjectsDir === undefined) {
        delete process.env.CLAUDE_PROJECTS_DIR;
      } else {
        process.env.CLAUDE_PROJECTS_DIR = previousProjectsDir;
      }
    }
  });
});
