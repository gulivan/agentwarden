export const SAMPLE_DISPLAY_MODES = ['none', 'masked', 'raw'] as const;

export type SampleDisplayMode = (typeof SAMPLE_DISPLAY_MODES)[number];

export interface SampleDisplayOptions {
  rawSamples?: boolean;
  sampleDisplay?: SampleDisplayMode;
  samples?: boolean;
}

export function resolveSampleDisplayMode(options: SampleDisplayOptions = {}): SampleDisplayMode {
  if (options.sampleDisplay !== undefined) {
    return options.sampleDisplay;
  }

  if (options.rawSamples) {
    return 'raw';
  }

  if (options.samples) {
    return 'masked';
  }

  return 'none';
}

export function includesSamples(mode: SampleDisplayMode): boolean {
  return mode !== 'none';
}

export function usesRawSamples(mode: SampleDisplayMode): boolean {
  return mode === 'raw';
}
