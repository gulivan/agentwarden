import { createBackups } from '../io/backup.js';
import type { AgentProvider, ProviderNotice } from '../providers/types.js';
import { analyzeArtifacts } from '../secrets/plan.js';
import { loadArtifacts, shouldFailRequestedProvider } from './helpers.js';

export interface MaskSecretsCommandOptions {
  agent?: AgentProvider;
  dryRun?: boolean;
  backup: boolean;
}

function formatNotices(notices: ProviderNotice[]): string[] {
  return notices.map((notice) => {
    const sessionSuffix = notice.sessionId === undefined ? '' : ` (${notice.sessionId})`;
    return `- ${notice.provider}${sessionSuffix}: ${notice.message}`;
  });
}

function printNoticeSection(label: string, notices: ProviderNotice[]): void {
  if (notices.length === 0) {
    return;
  }

  console.log('');
  console.log(`${label}:`);
  formatNotices(notices).forEach((line) => console.log(line));
}

function printMessageSection(label: string, messages: string[]): void {
  if (messages.length === 0) {
    return;
  }

  console.log('');
  console.log(`${label}:`);
  messages.forEach((message) => console.log(`- ${message}`));
}

export async function maskSecretsCommand(options: MaskSecretsCommandOptions): Promise<void> {
  const loaded = await loadArtifacts(options.agent);
  const analysis = analyzeArtifacts(loaded.artifacts);
  const shouldFail = shouldFailRequestedProvider(options.agent, loaded);

  if (analysis.summary.sessions === 0) {
    console.log('no sessions found');

    printNoticeSection('warnings', loaded.warnings);
    printNoticeSection('errors', loaded.errors);

    if (shouldFail) {
      process.exitCode = 1;
    }

    return;
  }

  const changedSessions = analysis.analyzedSessions.filter((session) => session.fieldPlans.length > 0);
  const totalFieldChanges = changedSessions.reduce((total, session) => total + session.fieldPlans.length, 0);

  if (changedSessions.length === 0) {
    console.log('no secrets detected');

    printNoticeSection('warnings', loaded.warnings);
    printNoticeSection('errors', loaded.errors);

    if (shouldFail) {
      process.exitCode = 1;
    }

    return;
  }

  if (options.dryRun) {
    console.log(`would change ${totalFieldChanges} fields across ${changedSessions.length} sessions`);

    printNoticeSection('warnings', loaded.warnings);
    printNoticeSection('errors', loaded.errors);

    if (shouldFail) {
      process.exitCode = 1;
    }

    return;
  }

  const artifactsToWrite = changedSessions.map((session) => session.artifact);
  let backupResult;

  if (options.backup) {
    try {
      backupResult = await createBackups(artifactsToWrite);
    } catch (error) {
      console.log('backup failed');
      printNoticeSection('warnings', loaded.warnings);
      printNoticeSection('errors', loaded.errors);
      printMessageSection('errors', [error instanceof Error ? error.message : String(error)]);
      process.exitCode = 1;
      return;
    }
  }

  const writeWarnings: ProviderNotice[] = [];
  const writeErrors: ProviderNotice[] = [...loaded.errors];
  const writtenTargets = new Set<string>();
  let updatedSessions = 0;

  for (const session of changedSessions) {
    for (const fieldPlan of session.fieldPlans) {
      fieldPlan.field.setValue(fieldPlan.nextValue);
    }

    try {
      const persistResult = await session.artifact.writeChanges();
      persistResult.warnings.forEach((warning) => writeWarnings.push(warning));
      persistResult.writes.forEach((writeTarget) => writtenTargets.add(writeTarget));

      if (persistResult.writes.length > 0) {
        updatedSessions += 1;
      }
    } catch (error) {
      writeErrors.push({
        provider: session.artifact.handle.provider,
        level: 'error',
        sessionId: session.artifact.handle.sessionId,
        message: error instanceof Error ? error.message : String(error),
      });
    }
  }

  console.log(`updated ${updatedSessions} sessions`);
  console.log(`changed fields: ${totalFieldChanges}`);
  console.log(`backups: ${backupResult?.root ?? 'disabled'}`);

  if (backupResult !== undefined) {
    console.log(`manifest: ${backupResult.manifestPath}`);
  }

  console.log(`writes: ${writtenTargets.size}`);

  const combinedWarnings = [...loaded.warnings, ...writeWarnings];

  printNoticeSection('warnings', combinedWarnings);

  if (writeErrors.length > 0) {
    printNoticeSection('errors', writeErrors);
    process.exitCode = 1;
    return;
  }

  if (shouldFail) {
    process.exitCode = 1;
  }
}
