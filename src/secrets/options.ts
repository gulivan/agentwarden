import { SECRET_TYPES, type SecretType } from './types.js';

export interface DetectionOptions {
  enabledTypes?: ReadonlySet<SecretType>;
}

export interface SecretTypeSelection {
  includeTypes?: SecretType[];
  excludeTypes?: SecretType[];
}

export interface ResolvedSecretTypeSelection extends DetectionOptions {
  includeTypes: SecretType[];
  excludeTypes: SecretType[];
  checkedTypes: SecretType[];
  allTypesEnabled: boolean;
}

function orderSecretTypes(types: readonly SecretType[]): SecretType[] {
  const selected = new Set(types);
  return SECRET_TYPES.filter((type) => selected.has(type));
}

export function resolveSecretTypeSelection(selection: SecretTypeSelection = {}): ResolvedSecretTypeSelection {
  const includeTypes = orderSecretTypes(selection.includeTypes ?? []);
  const excludeTypes = orderSecretTypes(selection.excludeTypes ?? []);
  const enabledTypes = new Set<SecretType>(includeTypes.length > 0 ? includeTypes : SECRET_TYPES);

  excludeTypes.forEach((type) => enabledTypes.delete(type));

  const checkedTypes = SECRET_TYPES.filter((type) => enabledTypes.has(type));

  return {
    includeTypes,
    excludeTypes,
    checkedTypes,
    allTypesEnabled: includeTypes.length === 0 && excludeTypes.length === 0,
    enabledTypes,
  };
}

export function isSecretTypeEnabled(type: SecretType, options?: DetectionOptions): boolean {
  return options?.enabledTypes === undefined || options.enabledTypes.has(type);
}

export function formatSecretTypes(types: readonly SecretType[]): string {
  return types.length === 0 ? 'none' : types.join(', ');
}
