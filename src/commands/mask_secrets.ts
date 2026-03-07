import { createBackups } from '../io/backup.js';
import type { AgentProvider, ProviderNotice } from '../providers/types.js';
import { formatSecretTypes, resolveSecretTypeSelection } from '../secrets/options.js';
import { analyzeArtifacts } from '../secrets/plan.js';
import type { SecretType } from '../secrets/types.js';
import { loadArtifacts, resolveProviderSelection, shouldFailRequestedProvider } from './helpers.js';

const ANSI_RESET = '\x1B[0m';
const ANSI_RED = '\x1B[31m';
const ANSI_BOLD = '\x1B[1m';

function formatDangerMessage(message: string): string {
  if (process.stdout.isTTY !== true || process.env.NO_COLOR !== undefined) {
    return message;
  }

  return `${ANSI_RED}${ANSI_BOLD}${message}${ANSI_RESET}`;
}

export interface MaskSecretsCommandOptions {
  agent?: AgentProvider;
  agents?: AgentProvider[];
  backup: boolean;
  dryRun?: boolean;
  types?: SecretType[];
  excludeTypes?: SecretType[];
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

function printCheckedTypesIfFiltered(allTypesEnabled: boolean, checkedTypes: SecretType[]): void {
  if (allTypesEnabled) {
    return;
  }

  console.log(`checked types: ${formatSecretTypes(checkedTypes)}`);
}

export async function maskSecretsCommand(options: MaskSecretsCommandOptions): Promise<void> {
  const requestedProviders = resolveProviderSelection(options);
  const detectionOptions = resolveSecretTypeSelection({
    includeTypes: options.types,
    excludeTypes: options.excludeTypes,
  });
  const loaded = await loadArtifacts({ agent: options.agent, agents: options.agents });
  const analysis = analyzeArtifacts(loaded.artifacts, detectionOptions);
  const shouldFail = shouldFailRequestedProvider(requestedProviders, loaded);

  if (analysis.summary.sessions === 0) {
    console.log('no sessions found');
    printCheckedTypesIfFiltered(detectionOptions.allTypesEnabled, detectionOptions.checkedTypes);

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
    printCheckedTypesIfFiltered(detectionOptions.allTypesEnabled, detectionOptions.checkedTypes);

    printNoticeSection('warnings', loaded.warnings);
    printNoticeSection('errors', loaded.errors);

    if (shouldFail) {
      process.exitCode = 1;
    }

    return;
  }

  if (options.dryRun) {
    console.log(`would change ${totalFieldChanges} fields across ${changedSessions.length} sessions`);
    printCheckedTypesIfFiltered(detectionOptions.allTypesEnabled, detectionOptions.checkedTypes);

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
      printCheckedTypesIfFiltered(detectionOptions.allTypesEnabled, detectionOptions.checkedTypes);
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
  printCheckedTypesIfFiltered(detectionOptions.allTypesEnabled, detectionOptions.checkedTypes);
  console.log(`backups: ${backupResult?.root ?? 'disabled'}`);

  if (backupResult !== undefined) {
    console.log(`manifest: ${backupResult.manifestPath}`);
    console.log(formatDangerMessage(`warning: original unmasked secrets remain in backups at ${backupResult.root}`));
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
