#!/usr/bin/env bun

import { Command, InvalidArgumentError } from 'commander';
import { maskSecretsCommand } from './commands/mask_secrets.js';
import { scanCommand } from './commands/scan.js';
import { isAgentProvider, orderAgentProviders } from './providers/index.js';
import { AGENT_PROVIDERS, type AgentProvider } from './providers/types.js';
import { expandSecretFilterTokens, formatSecretFilterChoices } from './secrets/catalog.js';
import { type SecretType } from './secrets/types.js';

const packageMetadata = (await Bun.file(new URL('../package.json', import.meta.url)).json()) as { version?: string };
const program = new Command();

function parseAgentProvider(value: string): AgentProvider {
  if (!isAgentProvider(value)) {
    throw new InvalidArgumentError(`Expected one of: ${AGENT_PROVIDERS.join(', ')}`);
  }

  return value;
}

function parseAgentProviders(value: string, previous: AgentProvider[] = []): AgentProvider[] {
  const parts = value
    .split(',')
    .map((part) => part.trim())
    .filter((part) => part.length > 0);

  if (parts.length === 0) {
    throw new InvalidArgumentError(`Expected a comma-separated list of providers: ${AGENT_PROVIDERS.join(', ')}`);
  }

  const invalid = parts.filter((part) => !isAgentProvider(part));

  if (invalid.length > 0) {
    throw new InvalidArgumentError(`Unknown provider(s): ${invalid.join(', ')}. Expected one of: ${AGENT_PROVIDERS.join(', ')}`);
  }

  return orderAgentProviders([...previous, ...(parts as AgentProvider[])]);
}

function parseSecretTypes(value: string, previous: SecretType[] = []): SecretType[] {
  const parts = value
    .split(',')
    .map((part) => part.trim())
    .filter((part) => part.length > 0);

  if (parts.length === 0) {
    throw new InvalidArgumentError(`Expected a comma-separated list of types or groups: ${formatSecretFilterChoices()}`);
  }

  const expanded = expandSecretFilterTokens(parts);

  if (expanded.invalid.length > 0) {
    throw new InvalidArgumentError(
      `Unknown type(s): ${expanded.invalid.join(', ')}. Expected one of: ${formatSecretFilterChoices()}`,
    );
  }

  return [...new Set([...previous, ...expanded.types])];
}

program
  .name('agentwarden')
  .description('Agent Warden CLI - A TypeScript CLI application')
  .version(packageMetadata.version ?? '0.0.0');

program
  .command('scan')
  .description('Scan agent session storage for secrets')
  .option('-a, --agent <agent>', 'agent provider to scan', parseAgentProvider)
  .option('--agents <agents>', 'comma-separated providers to scan', parseAgentProviders)
  .option('--json', 'emit JSON output')
  .option('--details', 'show per-session finding details')
  .option('--samples', 'show masked sample values in the report')
  .option('--raw-samples', 'show unmasked sample values in the report (sensitive)')
  .option('--types <types>', 'comma-separated finding types or groups to include', parseSecretTypes)
  .option('--exclude-types <types>', 'comma-separated finding types or groups to skip', parseSecretTypes)
  .option('--interactive', 'run the scan wizard even when flags are present')
  .option('--direct', 'skip the interactive scan wizard')
  .action(scanCommand);

program
  .command('mask_secrets')
  .description('Mask detected secrets in agent session storage')
  .option('-a, --agent <agent>', 'agent provider to mask', parseAgentProvider)
  .option('--agents <agents>', 'comma-separated providers to mask', parseAgentProviders)
  .option('--dry-run', 'show planned changes without writing')
  .option('--types <types>', 'comma-separated finding types or groups to include', parseSecretTypes)
  .option('--exclude-types <types>', 'comma-separated finding types or groups to skip', parseSecretTypes)
  .option('--no-backup', 'disable backups for writes')
  .action(maskSecretsCommand);

await program.parseAsync();
