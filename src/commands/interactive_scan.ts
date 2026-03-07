import { clearLine, cursorTo, emitKeypressEvents, moveCursor } from 'node:readline';
import type { Key } from 'node:readline';
import { stdin as input, stdout as output } from 'node:process';
import { expandHomeDir } from '../io/paths.js';
import { type SampleDisplayMode } from '../reporting/sample_display.js';
import { getProviderReaders } from '../providers/index.js';
import { AGENT_PROVIDERS, type AgentProvider } from '../providers/types.js';
import { getSecretTypeDefinition, SECRET_TYPE_GROUPS } from '../secrets/catalog.js';
import { formatSecretTypes } from '../secrets/options.js';
import { SECRET_TYPES, type SecretType } from '../secrets/types.js';
import { formatProviderSelection } from './helpers.js';

export interface InteractiveScanSelection {
  agents?: AgentProvider[];
  sampleDisplayMode: SampleDisplayMode;
  types?: SecretType[];
}

export type PostScanAction = 'show_spotted_stats' | 'save_to_file' | 'skip';

interface MenuCommand<T> {
  kind: 'submit' | 'update' | 'cancel';
  clearStatus?: boolean;
  status?: string;
  value?: T;
}

interface SingleChoiceDetailLine {
  danger?: boolean;
  text: string;
}

interface SingleChoiceOption<T> {
  danger?: boolean;
  description: string;
  details?: SingleChoiceDetailLine[];
  label: string;
  value: T;
}

export type MaskDecision = 'with_backups' | 'without_backups' | 'skip';

type ProviderMenuItem =
  | { kind: 'all'; label: string }
  | { description: string; kind: 'provider'; label: string; provider: AgentProvider };

type SecretMenuItem =
  | { kind: 'all'; label: string }
  | { description: string; kind: 'group'; label: string; types: readonly SecretType[] }
  | { description: string; example: string; kind: 'type'; label: string; type: SecretType };

type ProviderSessionCounts = Partial<Record<AgentProvider, number | undefined>>;

const ANSI_RESET = '\x1B[0m';
const ANSI_BOLD = '\x1B[1m';
const ANSI_DIM = '\x1B[2m';
const ANSI_RED = '\x1B[31m';
const ANSI_GREEN = '\x1B[32m';
const ANSI_YELLOW = '\x1B[33m';
const ANSI_CYAN = '\x1B[36m';
const ANSI_GRAY = '\x1B[90m';

const PROVIDER_MENU_ITEMS: ProviderMenuItem[] = [
  { kind: 'all', label: 'All clients' },
  { kind: 'provider', label: 'codex', provider: 'codex', description: 'Scan Codex session storage.' },
  { kind: 'provider', label: 'claude', provider: 'claude', description: 'Scan Claude session storage.' },
  { kind: 'provider', label: 'gemini', provider: 'gemini', description: 'Scan Gemini session storage.' },
  { kind: 'provider', label: 'opencode', provider: 'opencode', description: 'Scan OpenCode session storage.' },
];

const SECRET_MENU_ITEMS: SecretMenuItem[] = [
  { kind: 'all', label: 'All finding types' },
  ...SECRET_TYPE_GROUPS.flatMap((group) => [
    {
      kind: 'group' as const,
      label: `${group.id} — ${group.label}${group.id === 'user_data' ? ' (non-security)' : ''}`,
      description: group.description,
      types: group.types,
    },
    ...(('showMembers' in group && group.showMembers === false)
      ? []
      : group.types.map((type) => {
          const definition = getSecretTypeDefinition(type);
          return {
            kind: 'type' as const,
            label: type,
            description: definition.description,
            example: definition.example,
            type,
          };
        })),
  ]),
];

function supportsAnsiColors(): boolean {
  if (output.isTTY !== true || process.env.NO_COLOR !== undefined) {
    return false;
  }

  return typeof output.hasColors !== 'function' || output.hasColors();
}

function paint(text: string, ...codes: string[]): string {
  if (!supportsAnsiColors() || codes.length === 0) {
    return text;
  }

  return `${codes.join('')}${text}${ANSI_RESET}`;
}

function renderTitle(text: string): string {
  return paint(text, ANSI_BOLD);
}

function renderHelpText(text: string): string {
  return paint(text, ANSI_DIM);
}

function renderCursor(active: boolean, danger = false): string {
  if (!active) {
    return ' ';
  }

  return danger ? paint('›', ANSI_RED, ANSI_BOLD) : paint('›', ANSI_CYAN, ANSI_BOLD);
}

function renderStatus(text: string): string {
  return paint(text, ANSI_RED, ANSI_BOLD);
}

function renderSectionHeading(text: string): string {
  return paint(text, ANSI_BOLD);
}

function renderDangerText(text: string): string {
  return paint(text, ANSI_RED, ANSI_BOLD);
}

function getBackupRootPattern(): string {
  return `${expandHomeDir('~/.agentwarden/backups')}/<timestamp>-mask_secrets`;
}

function renderMenuLabel(label: string, options: { active: boolean; caution?: boolean; selected: boolean }): string {
  if (options.selected) {
    return paint(label, ANSI_GREEN, ANSI_BOLD);
  }

  if (options.caution) {
    return paint(label, ANSI_YELLOW, options.active ? ANSI_BOLD : '');
  }

  if (options.active) {
    return paint(label, ANSI_CYAN, ANSI_BOLD);
  }

  return label;
}

function renderDetailLine(line: string, caution = false): string {
  return caution ? paint(line, ANSI_YELLOW) : line;
}

function formatProviderLabel(item: ProviderMenuItem, sessionCounts: ProviderSessionCounts): string {
  if (item.kind === 'all') {
    return item.label;
  }

  const count = sessionCounts[item.provider];
  return `${item.label} (${count ?? '?'})`;
}

function isProviderItemSelected(selectedProviders: ReadonlySet<AgentProvider>, item: ProviderMenuItem): boolean {
  if (item.kind === 'all') {
    return selectedProviders.size === AGENT_PROVIDERS.length;
  }

  return selectedProviders.has(item.provider);
}

function isNonSecuritySecretItem(item: SecretMenuItem): boolean {
  if (item.kind === 'all') {
    return false;
  }

  if (item.kind === 'group') {
    return item.types.every((type) => getSecretTypeDefinition(type).groupId === 'user_data');
  }

  return getSecretTypeDefinition(item.type).groupId === 'user_data';
}

function isSecretItemSelected(selectedTypes: ReadonlySet<SecretType>, item: SecretMenuItem): boolean {
  if (item.kind === 'all') {
    return selectedTypes.size === SECRET_TYPES.length;
  }

  if (item.kind === 'group') {
    return item.types.every((type) => selectedTypes.has(type));
  }

  return selectedTypes.has(item.type);
}

async function discoverProviderSessionCounts(): Promise<ProviderSessionCounts> {
  const counts = await Promise.all(
    getProviderReaders().map(async (reader) => {
      try {
        const discovery = await reader.discoverSessions();
        return [reader.provider, discovery.sessions.length] as const;
      } catch {
        return [reader.provider, undefined] as const;
      }
    }),
  );

  return Object.fromEntries(counts) as ProviderSessionCounts;
}

function clearRenderedLines(lineCount: number): void {
  if (lineCount === 0) {
    return;
  }

  clearLine(output, 0);

  for (let index = 1; index < lineCount; index += 1) {
    moveCursor(output, 0, -1);
    cursorTo(output, 0);
    clearLine(output, 0);
  }

  cursorTo(output, 0);
}

function renderIndicator(selected: boolean, partial = false): string {
  if (partial) {
    return paint('[-]', ANSI_YELLOW, ANSI_BOLD);
  }

  return selected ? paint('[x]', ANSI_GREEN, ANSI_BOLD) : paint('[ ]', ANSI_GRAY);
}

export interface RawMenuInputController {
  isTTY?: boolean;
  off(eventName: 'keypress', listener: (sequence: string, key: Key) => void): void;
  pause(): void;
  setRawMode?(mode: boolean): void;
}

export function cleanupRawMenuInput(
  ttyInput: RawMenuInputController,
  handleKeypress: (sequence: string, key: Key) => void,
  wasRaw: boolean,
): void {
  ttyInput.off('keypress', handleKeypress);

  if (ttyInput.isTTY === true && !wasRaw) {
    ttyInput.setRawMode?.(false);
  }

  ttyInput.pause();
}

function wrapIndex(nextIndex: number, total: number): number {
  if (total === 0) {
    return 0;
  }

  return (nextIndex + total) % total;
}

async function runRawMenu<T>(
  render: (status?: string) => string[],
  onKeypress: (key: Key, sequence: string) => MenuCommand<T>,
): Promise<T | undefined> {
  return await new Promise<T | undefined>((resolve) => {
    emitKeypressEvents(input);

    const ttyInput = input;
    const wasRaw = ttyInput.isTTY === true && ttyInput.isRaw === true;
    let renderedLineCount = 0;
    let status: string | undefined;

    const rerender = (): void => {
      clearRenderedLines(renderedLineCount);
      const lines = render(status);
      output.write(lines.join('\n'));
      renderedLineCount = lines.length;
    };

    const finish = (value: T | undefined): void => {
      cleanupRawMenuInput(ttyInput, handleKeypress, wasRaw);

      output.write('\x1B[?25h');
      clearRenderedLines(renderedLineCount);
      resolve(value);
    };

    const handleKeypress = (sequence: string, key: Key): void => {
      if (key.ctrl === true && key.name === 'c') {
        finish(undefined);
        return;
      }

      const command = onKeypress(key, sequence);

      if (command.kind === 'submit') {
        finish(command.value);
        return;
      }

      if (command.kind === 'cancel') {
        finish(undefined);
        return;
      }

      if (command.clearStatus === true) {
        status = undefined;
      }

      if (command.status !== undefined) {
        status = command.status;
      }

      rerender();
    };

    if (ttyInput.isTTY === true && !wasRaw) {
      ttyInput.setRawMode(true);
    }

    ttyInput.resume();
    output.write('\x1B[?25l');
    ttyInput.on('keypress', handleKeypress);
    rerender();
  });
}

function renderSingleChoice<T>(options: {
  contextLines?: string[];
  cursorIndex: number;
  helpText: string;
  options: SingleChoiceOption<T>[];
  status?: string;
  title: string;
}): string[] {
  const active = options.options[options.cursorIndex] ?? options.options[0];
  const lines = [renderTitle(options.title), renderHelpText(options.helpText), ''];

  if (options.contextLines !== undefined && options.contextLines.length > 0) {
    lines.push(...options.contextLines, '');
  }

  options.options.forEach((option, index) => {
    const activeOption = index === options.cursorIndex;
    const cursor = renderCursor(activeOption, option.danger === true);
    const label = option.danger ? renderDangerText(option.label) : renderMenuLabel(option.label, { active: activeOption, selected: false });
    lines.push(`${cursor} ${label}`);
  });

  if (active !== undefined) {
    lines.push('', renderSectionHeading('Details:'), `  ${active.danger ? renderDangerText(active.description) : active.description}`);

    active.details?.forEach((detail) => {
      lines.push(`  ${detail.danger ? renderDangerText(detail.text) : detail.text}`);
    });
  }

  if (options.status !== undefined) {
    lines.push('', renderStatus(options.status));
  }

  return lines;
}

async function promptSingleChoice<T>(options: {
  contextLines?: string[];
  defaultValue: T;
  helpText: string;
  options: SingleChoiceOption<T>[];
  title: string;
}): Promise<T | undefined> {
  let cursorIndex = Math.max(
    0,
    options.options.findIndex((option) => Object.is(option.value, options.defaultValue)),
  );

  return await runRawMenu<T>(
    (status) =>
      renderSingleChoice({
        contextLines: options.contextLines,
        cursorIndex,
        helpText: options.helpText,
        options: options.options,
        status,
        title: options.title,
      }),
    (key) => {
      if (key.name === 'up' || key.name === 'k') {
        cursorIndex = wrapIndex(cursorIndex - 1, options.options.length);
        return { kind: 'update', clearStatus: true };
      }

      if (key.name === 'down' || key.name === 'j' || key.name === 'tab') {
        cursorIndex = wrapIndex(cursorIndex + 1, options.options.length);
        return { kind: 'update', clearStatus: true };
      }

      if (key.name === 'return' || key.name === 'enter' || key.name === 'space') {
        return { kind: 'submit', value: options.options[cursorIndex]?.value };
      }

      if (key.name === 'escape') {
        return { kind: 'cancel' };
      }

      return { kind: 'update' };
    },
  );
}

function getProviderIndicator(selectedProviders: ReadonlySet<AgentProvider>, item: ProviderMenuItem): string {
  if (item.kind === 'all') {
    const selectedCount = selectedProviders.size;
    return renderIndicator(selectedCount === AGENT_PROVIDERS.length, selectedCount > 0 && selectedCount < AGENT_PROVIDERS.length);
  }

  return renderIndicator(selectedProviders.has(item.provider));
}

function getProviderDetails(
  item: ProviderMenuItem,
  selectedProviders: ReadonlySet<AgentProvider>,
  sessionCounts: ProviderSessionCounts,
): string[] {
  if (item.kind === 'all') {
    return [
      'Scans every supported client session store.',
      `Currently selected: ${selectedProviders.size === AGENT_PROVIDERS.length ? 'all clients' : formatProviderSelection(AGENT_PROVIDERS.filter((provider) => selectedProviders.has(provider)))}`,
    ];
  }

  return [item.description, `Detected sessions: ${sessionCounts[item.provider] ?? 'unknown'}`];
}

async function promptProviderSelection(
  defaults?: AgentProvider[],
  sessionCounts: ProviderSessionCounts = {},
): Promise<AgentProvider[] | undefined> {
  const selectedProviders = new Set<AgentProvider>(defaults ?? AGENT_PROVIDERS);
  let cursorIndex = 0;

  return await runRawMenu<AgentProvider[]>(
    (status) => {
      const activeItem = PROVIDER_MENU_ITEMS[cursorIndex] ?? PROVIDER_MENU_ITEMS[0];
      const lines = [
        renderTitle('Select clients'),
        renderHelpText('Use ↑/↓ to move, space to toggle, enter to continue, esc to cancel.'),
        '',
      ];

      PROVIDER_MENU_ITEMS.forEach((item, index) => {
        const active = index === cursorIndex;
        const cursor = renderCursor(active);
        lines.push(
          `${cursor} ${getProviderIndicator(selectedProviders, item)} ${renderMenuLabel(formatProviderLabel(item, sessionCounts), { active, selected: isProviderItemSelected(selectedProviders, item) })}`,
        );
      });

      if (activeItem !== undefined) {
        lines.push(
          '',
          renderSectionHeading('Details:'),
          ...getProviderDetails(activeItem, selectedProviders, sessionCounts).map((line) => `  ${line}`),
        );
      }

      if (status !== undefined) {
        lines.push('', renderStatus(status));
      }

      return lines;
    },
    (key) => {
      if (key.name === 'up' || key.name === 'k') {
        cursorIndex = wrapIndex(cursorIndex - 1, PROVIDER_MENU_ITEMS.length);
        return { kind: 'update', clearStatus: true };
      }

      if (key.name === 'down' || key.name === 'j' || key.name === 'tab') {
        cursorIndex = wrapIndex(cursorIndex + 1, PROVIDER_MENU_ITEMS.length);
        return { kind: 'update', clearStatus: true };
      }

      if (key.name === 'space') {
        const item = PROVIDER_MENU_ITEMS[cursorIndex];

        if (item === undefined) {
          return { kind: 'update' };
        }

        if (item.kind === 'all') {
          if (selectedProviders.size === AGENT_PROVIDERS.length) {
            selectedProviders.clear();
          } else {
            AGENT_PROVIDERS.forEach((provider) => selectedProviders.add(provider));
          }
        } else if (selectedProviders.size === AGENT_PROVIDERS.length) {
          selectedProviders.clear();
          selectedProviders.add(item.provider);
        } else if (selectedProviders.has(item.provider)) {
          selectedProviders.delete(item.provider);
        } else {
          selectedProviders.add(item.provider);
        }

        return { kind: 'update', clearStatus: true };
      }

      if (key.name === 'return' || key.name === 'enter') {
        if (selectedProviders.size === 0) {
          return { kind: 'update', status: 'Select at least one client.' };
        }

        return { kind: 'submit', value: AGENT_PROVIDERS.filter((provider) => selectedProviders.has(provider)) };
      }

      if (key.name === 'escape') {
        return { kind: 'cancel' };
      }

      return { kind: 'update' };
    },
  );
}

function getTypeGroupIndicator(selectedTypes: ReadonlySet<SecretType>, groupTypes: readonly SecretType[]): string {
  const selectedCount = groupTypes.filter((type) => selectedTypes.has(type)).length;
  return renderIndicator(selectedCount === groupTypes.length, selectedCount > 0 && selectedCount < groupTypes.length);
}

function getSecretIndicator(selectedTypes: ReadonlySet<SecretType>, item: SecretMenuItem): string {
  if (item.kind === 'all') {
    return renderIndicator(selectedTypes.size === SECRET_TYPES.length, selectedTypes.size > 0 && selectedTypes.size < SECRET_TYPES.length);
  }

  if (item.kind === 'group') {
    return getTypeGroupIndicator(selectedTypes, item.types);
  }

  return renderIndicator(selectedTypes.has(item.type));
}

function getSecretDetails(item: SecretMenuItem, selectedTypes: ReadonlySet<SecretType>): string[] {
  const detailsPrefix = isNonSecuritySecretItem(item) ? ['Non-security finding type.'] : [];

  if (item.kind === 'all') {
    return [
      'Checks every available finding type.',
      `Currently selected: ${selectedTypes.size === SECRET_TYPES.length ? 'all types' : `${selectedTypes.size} type${selectedTypes.size === 1 ? '' : 's'}`}`,
    ];
  }

  if (item.kind === 'group') {
    return [...detailsPrefix, item.description, `Includes: ${item.types.join(', ')}`];
  }

  return [...detailsPrefix, item.description, `Example: ${item.example}`];
}

async function promptSecretTypeSelection(defaults?: SecretType[]): Promise<SecretType[] | undefined> {
  const selectedTypes = new Set<SecretType>(defaults ?? SECRET_TYPES);
  let cursorIndex = 0;

  return await runRawMenu<SecretType[]>(
    (status) => {
      const activeItem = SECRET_MENU_ITEMS[cursorIndex] ?? SECRET_MENU_ITEMS[0];
      const lines = [
        renderTitle('Select finding types'),
        renderHelpText('Use ↑/↓ to move, space to toggle, enter to continue, esc to cancel.'),
        '',
      ];

      SECRET_MENU_ITEMS.forEach((item, index) => {
        const active = index === cursorIndex;
        const cursor = renderCursor(active);
        const indent = item.kind === 'type' ? '  ' : '';
        lines.push(
          `${cursor} ${getSecretIndicator(selectedTypes, item)} ${renderMenuLabel(`${indent}${item.label}`, {
            active,
            caution: isNonSecuritySecretItem(item),
            selected: isSecretItemSelected(selectedTypes, item),
          })}`,
        );
      });

      if (activeItem !== undefined) {
        lines.push(
          '',
          renderSectionHeading('Details:'),
          ...getSecretDetails(activeItem, selectedTypes).map((line) => `  ${renderDetailLine(line, isNonSecuritySecretItem(activeItem))}`),
        );
      }

      if (status !== undefined) {
        lines.push('', renderStatus(status));
      }

      return lines;
    },
    (key) => {
      if (key.name === 'up' || key.name === 'k') {
        cursorIndex = wrapIndex(cursorIndex - 1, SECRET_MENU_ITEMS.length);
        return { kind: 'update', clearStatus: true };
      }

      if (key.name === 'down' || key.name === 'j' || key.name === 'tab') {
        cursorIndex = wrapIndex(cursorIndex + 1, SECRET_MENU_ITEMS.length);
        return { kind: 'update', clearStatus: true };
      }

      if (key.name === 'space') {
        const item = SECRET_MENU_ITEMS[cursorIndex];

        if (item === undefined) {
          return { kind: 'update' };
        }

        if (item.kind === 'all') {
          if (selectedTypes.size === SECRET_TYPES.length) {
            selectedTypes.clear();
          } else {
            SECRET_TYPES.forEach((type) => selectedTypes.add(type));
          }
        } else if (item.kind === 'group') {
          if (selectedTypes.size === SECRET_TYPES.length) {
            selectedTypes.clear();
            item.types.forEach((type) => selectedTypes.add(type));
          } else {
            const allSelected = item.types.every((type) => selectedTypes.has(type));

            if (allSelected) {
              item.types.forEach((type) => selectedTypes.delete(type));
            } else {
              item.types.forEach((type) => selectedTypes.add(type));
            }
          }
        } else if (selectedTypes.size === SECRET_TYPES.length) {
          selectedTypes.clear();
          selectedTypes.add(item.type);
        } else if (selectedTypes.has(item.type)) {
          selectedTypes.delete(item.type);
        } else {
          selectedTypes.add(item.type);
        }

        return { kind: 'update', clearStatus: true };
      }

      if (key.name === 'return' || key.name === 'enter') {
        if (selectedTypes.size === 0) {
          return { kind: 'update', status: 'Select at least one finding type.' };
        }

        return { kind: 'submit', value: SECRET_TYPES.filter((type) => selectedTypes.has(type)) };
      }

      if (key.name === 'escape') {
        return { kind: 'cancel' };
      }

      return { kind: 'update' };
    },
  );
}

function isAllTypesSelected(types: readonly SecretType[] | undefined): boolean {
  return types === undefined || types.length === 0 || types.length === SECRET_TYPES.length;
}

export function canPromptInteractively(): boolean {
  return process.stdin.isTTY === true && process.stdout.isTTY === true;
}

export async function promptForInteractiveScan(
  defaults: Partial<InteractiveScanSelection> = {},
): Promise<InteractiveScanSelection | undefined> {
  const providerSessionCounts = await discoverProviderSessionCounts();
  const selectedProviders = await promptProviderSelection(defaults.agents, providerSessionCounts);

  if (selectedProviders === undefined) {
    return undefined;
  }

  const selectedTypes = await promptSecretTypeSelection(defaults.types);

  if (selectedTypes === undefined) {
    return undefined;
  }

  const sampleDisplayMode = await promptSingleChoice<SampleDisplayMode>({
    defaultValue: defaults.sampleDisplayMode ?? 'none',
    helpText: 'Use ↑/↓ to move, enter to choose, esc to cancel.',
    options: [
      {
        label: 'Summary only',
        value: 'none',
        description: 'Do not include sample values in the scan report.',
      },
      {
        label: 'Show masked examples',
        value: 'masked',
        description: 'Include masked sample values in the scan report.',
      },
      {
        label: 'Show raw values',
        value: 'raw',
        danger: true,
        description: 'Include unmasked values in the scan report. Sensitive output.',
      },
    ],
    title: 'How should sample values be shown?',
  });

  if (sampleDisplayMode === undefined) {
    return undefined;
  }

  const agents = selectedProviders.length === AGENT_PROVIDERS.length ? undefined : selectedProviders;
  const types = selectedTypes.length === SECRET_TYPES.length ? undefined : selectedTypes;
  const shouldScanNow = await promptSingleChoice<boolean>({
    contextLines: [
      `Clients: ${formatProviderSelection(agents)}`,
      `Finding types: ${isAllTypesSelected(types) ? 'all' : formatSecretTypes(types ?? [])}`,
      `Sample values: ${sampleDisplayMode}`,
    ],
    defaultValue: true,
    helpText: 'Use ↑/↓ to move, enter to choose, esc to cancel.',
    options: [
      { label: 'Scan now', value: true, description: 'Run the scan with the selections above.' },
      { label: 'Cancel', value: false, description: 'Exit the wizard without scanning.' },
    ],
    title: 'Review scan settings',
  });

  if (shouldScanNow !== true) {
    return undefined;
  }

  return {
    agents,
    sampleDisplayMode,
    types,
  };
}

export async function promptPostScanAction(): Promise<PostScanAction> {
  const action = await promptSingleChoice<PostScanAction>({
    defaultValue: 'skip',
    helpText: 'Use ↑/↓ to move, enter to choose, esc to continue.',
    options: [
      {
        label: 'Show spotted stats',
        value: 'show_spotted_stats',
        description: 'Show aggregated counts per detected entry across sessions and providers.',
      },
      {
        label: 'Save to file',
        value: 'save_to_file',
        description: 'Save the current report to a file in `.agentwarden-reports`.',
      },
      {
        label: 'Skip',
        value: 'skip',
        description: 'Continue without extra report actions.',
      },
    ],
    title: 'Post-scan actions',
  });

  return action ?? 'skip';
}

export async function promptToMaskDetectedSecrets(): Promise<MaskDecision> {
  const decision = await promptSingleChoice<MaskDecision>({
    defaultValue: 'skip',
    helpText: 'Use ↑/↓ to move, enter to choose, esc to keep files unchanged.',
    options: [
      {
        label: 'Mask and create backups',
        value: 'with_backups',
        description: 'Write masked values back to disk and preserve the original unmasked files.',
        details: [
          { danger: true, text: 'Warning: backups keep the original unmasked secrets on disk.' },
          { danger: true, text: `Backup path: ${getBackupRootPattern()}` },
        ],
      },
      {
        label: 'Mask and do not create backups',
        value: 'without_backups',
        description: 'Write masked values back to disk without preserving originals. Better for sanitization, but harder to undo.',
      },
      { label: 'Leave files unchanged', value: 'skip', description: 'Keep the report only and skip masking.' },
    ],
    title: 'Mask findings?',
  });

  return decision ?? 'skip';
}
