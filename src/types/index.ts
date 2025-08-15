export interface Config {
  verbose?: boolean;
  environment?: 'development' | 'production';
}

export interface AgentWardenOptions {
  config?: Config;
  version?: string;
}