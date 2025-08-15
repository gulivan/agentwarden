#!/usr/bin/env bun

import { Command } from 'commander';
import { startCommand } from './commands/start.js';
import { statusCommand } from './commands/status.js';

const program = new Command();

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

program.parse();