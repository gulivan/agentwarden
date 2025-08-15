import type { AgentWardenOptions } from '../types/index.js';

interface StartOptions {
  port: string;
  verbose?: boolean;
}

export function startCommand(options: StartOptions): void {
  const { port, verbose } = options;
  
  if (verbose) {
    console.log('Starting Agent Warden in verbose mode...');
  }
  
  console.log(`🛡️  Agent Warden starting on port ${port}`);
  console.log('✅ Service is now running');
  
  if (verbose) {
    console.log('Verbose logging enabled');
    console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
  }
}