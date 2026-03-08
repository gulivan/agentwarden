import { spawnSync } from 'node:child_process';
import { copyFile, mkdir } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const repositoryRoot = path.resolve(scriptDirectory, '..');
const manifestPath = path.join(repositoryRoot, 'native', 'session-scanner', 'Cargo.toml');

function getVendorKey(): string {
  return `${process.platform}-${process.arch}`;
}

function getBuildArtifactPath(): string {
  const targetRoot = path.join(repositoryRoot, 'native', 'session-scanner', 'target', 'release');

  switch (process.platform) {
    case 'darwin':
      return path.join(targetRoot, 'libagentwarden_session_scanner.dylib');
    case 'linux':
      return path.join(targetRoot, 'libagentwarden_session_scanner.so');
    case 'win32':
      return path.join(targetRoot, 'agentwarden_session_scanner.dll');
    default:
      throw new Error(`Unsupported native build platform: ${process.platform}`);
  }
}

async function main(): Promise<void> {
  const cargoCheck = spawnSync('cargo', ['--version'], {
    cwd: repositoryRoot,
    stdio: 'ignore',
  });

  if (cargoCheck.error !== undefined || cargoCheck.status !== 0) {
    console.warn('Skipping Rust scanner build because cargo is unavailable.');
    return;
  }

  const buildResult = spawnSync('cargo', ['build', '--release', '--manifest-path', manifestPath], {
    cwd: repositoryRoot,
    stdio: 'inherit',
  });

  if (buildResult.status !== 0) {
    process.exit(buildResult.status ?? 1);
  }

  const buildArtifactPath = getBuildArtifactPath();

  if (!existsSync(buildArtifactPath)) {
    throw new Error(`Native build completed but no artifact was found at ${buildArtifactPath}`);
  }

  const outputDirectory = path.join(repositoryRoot, 'vendor', getVendorKey());
  const outputPath = path.join(outputDirectory, 'agentwarden-session-scanner.node');
  const localOutputPath = path.join(repositoryRoot, 'native', 'session-scanner', 'index.node');

  await mkdir(outputDirectory, { recursive: true });
  await copyFile(buildArtifactPath, outputPath);
  await copyFile(buildArtifactPath, localOutputPath);

  console.log(`Built native scanner: ${path.relative(repositoryRoot, outputPath)}`);
}

await main();
