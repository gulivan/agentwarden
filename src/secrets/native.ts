import { existsSync } from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import type { StringFieldRef } from '../providers/types.js';
import { buildMaskedValue } from './detector.js';
import type { DetectionOptions } from './options.js';
import type { DetectionSpan } from './types.js';

interface NativeScannerModule {
  scanFieldsBatch(input: string): string;
}

interface NativeBatchInput {
  enabledTypes?: string[];
  fields: Array<{
    contextKey?: string;
    value: string;
  }>;
}

interface NativeBatchOutput {
  results: Array<{
    findings: DetectionSpan[];
    nextValue: string;
  }>;
}

const require = createRequire(import.meta.url);
const moduleDirectory = path.dirname(fileURLToPath(import.meta.url));
const vendorKey = `${process.platform}-${process.arch}`;
const nativeModuleCandidates = [
  path.resolve(moduleDirectory, '../../vendor', vendorKey, 'agentwarden-session-scanner.node'),
  path.resolve(moduleDirectory, '../../native/session-scanner/index.node'),
];

let cachedNativeModule: NativeScannerModule | null | undefined;

function containsAstralCodePoint(value: string): boolean {
  return /[\uD800-\uDBFF][\uDC00-\uDFFF]/.test(value);
}

function getNativeModule(): NativeScannerModule | undefined {
  if (process.env.AGENTWARDEN_DISABLE_RUST_SCANNER === '1') {
    return undefined;
  }

  if (cachedNativeModule !== undefined) {
    return cachedNativeModule ?? undefined;
  }

  for (const candidate of nativeModuleCandidates) {
    if (!existsSync(candidate)) {
      continue;
    }

    try {
      cachedNativeModule = require(candidate) as NativeScannerModule;
      return cachedNativeModule;
    } catch {
      cachedNativeModule = null;
    }
  }

  cachedNativeModule = null;
  return undefined;
}

function buildNativeInput(fields: readonly StringFieldRef[], detectionOptions?: DetectionOptions): NativeBatchInput {
  return {
    enabledTypes: detectionOptions?.enabledTypes === undefined ? undefined : [...detectionOptions.enabledTypes],
    fields: fields.map((field) => ({
      contextKey: field.contextKey,
      value: field.value,
    })),
  };
}

export function buildMaskedValuesBatch(
  fields: readonly StringFieldRef[],
  detectionOptions?: DetectionOptions,
): Array<{ nextValue: string; findings: DetectionSpan[] }> {
  const nativeModule = getNativeModule();

  if (nativeModule === undefined || fields.length === 0) {
    return fields.map((field) => buildMaskedValue(field, detectionOptions));
  }

  const nativeResults = new Array<{ nextValue: string; findings: DetectionSpan[] } | undefined>(fields.length);
  const nativeFields: StringFieldRef[] = [];
  const nativeIndices: number[] = [];

  fields.forEach((field, index) => {
    if (containsAstralCodePoint(field.value)) {
      nativeResults[index] = buildMaskedValue(field, detectionOptions);
      return;
    }

    nativeFields.push(field);
    nativeIndices.push(index);
  });

  if (nativeFields.length > 0) {
    try {
      const rawOutput = nativeModule.scanFieldsBatch(JSON.stringify(buildNativeInput(nativeFields, detectionOptions)));
      const parsedOutput = JSON.parse(rawOutput) as NativeBatchOutput;

      parsedOutput.results.forEach((result, index) => {
        const targetIndex = nativeIndices[index];

        if (targetIndex === undefined) {
          return;
        }

        nativeResults[targetIndex] = result;
      });
    } catch {
      nativeFields.forEach((field, index) => {
        const targetIndex = nativeIndices[index];

        if (targetIndex === undefined) {
          return;
        }

        nativeResults[targetIndex] = buildMaskedValue(field, detectionOptions);
      });
    }
  }

  return nativeResults.map((result, index) => result ?? buildMaskedValue(fields[index]!, detectionOptions));
}
