#!/usr/bin/env bun

import { Command } from 'commander';
import { InvalidArgumentError } from 'commander';
import { maskSecretsCommand } from './commands/mask_secrets.js';
import { scanCommand } from './commands/scan.js';
import { startCommand } from './commands/start.js';
import { statusCommand } from './commands/status.js';
import { AGENT_PROVIDERS, type AgentProvider } from './providers/types.js';

const program = new Command();

function parseAgentProvider(value: string): AgentProvider {
  if (!AGENT_PROVIDERS.includes(value as AgentProvider)) {
    throw new InvalidArgumentError(`Expected one of: ${AGENT_PROVIDERS.join(', ')}`);
  }

  return value as AgentProvider;
}

program
  .name('agentwarden')
  .description('Agent Warden CLI - A TypeScript CLI application')
  .version('1.0.0');

program
  .command('start')
  .description('Start the Agent Warden service')
  .option('-p, --port <port>', 'port to run on', '3000')
  .option('-v, --verbose', 'verbose output')
  .action(startCommand);

program
  .command('status')
  .description('Check the status of Agent Warden service')
  .action(statusCommand);

program
  .command('scan')
  .description('Scan agent session storage for secrets')
  .option('-a, --agent <agent>', 'agent provider to scan', parseAgentProvider)
  .option('--json', 'emit JSON output')
  .action(scanCommand);

program
  .command('mask_secrets')
  .description('Mask detected secrets in agent session storage')
  .option('-a, --agent <agent>', 'agent provider to mask', parseAgentProvider)
  .option('--dry-run', 'show planned changes without writing')
  .option('--no-backup', 'disable backups for writes')
  .action(maskSecretsCommand);

await program.parseAsync();
