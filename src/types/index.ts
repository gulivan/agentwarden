export interface Config {
  verbose?: boolean;
  environment?: 'development' | 'production';
}

export interface AgentWardenOptions {
  config?: Config;
  version?: string;
}

export * from '../providers/types.js';
export * from '../secrets/types.js';
