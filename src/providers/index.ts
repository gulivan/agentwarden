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

export function getProviderReaders(providers?: readonly AgentProvider[]): ProviderReader[] {
  if (providers === undefined || providers.length === 0) {
    return AGENT_PROVIDERS.map((provider) => PROVIDERS[provider]);
  }

  return providers.map((provider) => PROVIDERS[provider]);
}

export function isAgentProvider(value: string): value is AgentProvider {
  return AGENT_PROVIDERS.includes(value as AgentProvider);
}

export function orderAgentProviders(providers: readonly AgentProvider[]): AgentProvider[] {
  const selected = new Set(providers);
  return AGENT_PROVIDERS.filter((provider) => selected.has(provider));
}
