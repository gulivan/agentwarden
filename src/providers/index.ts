import { claudeProvider } from './claude.js';
import { codexProvider } from './codex.js';
import { geminiProvider } from './gemini.js';
import { opencodeProvider } from './opencode.js';
import { AGENT_PROVIDERS, type AgentProvider, type ProviderReader } from './types.js';

const PROVIDERS: Record<AgentProvider, ProviderReader> = {
  codex: codexProvider,
  claude: claudeProvider,
  gemini: geminiProvider,
  opencode: opencodeProvider,
};

export function getProviderReaders(agent?: AgentProvider): ProviderReader[] {
  return agent === undefined ? AGENT_PROVIDERS.map((provider) => PROVIDERS[provider]) : [PROVIDERS[agent]];
}

export function isAgentProvider(value: string): value is AgentProvider {
  return AGENT_PROVIDERS.includes(value as AgentProvider);
}
