# Agent Warden

A TypeScript CLI application built with Bun and Commander.js.

## Installation

To install dependencies:

```bash
bun install
```

## Usage

### Development

Run in development mode:

```bash
bun run dev
```

### Commands

Start the Agent Warden service:

```bash
bun run start -- start --port 3000
```

Check service status:

```bash
bun run start -- status
```

### Building

Build the project:

```bash
bun run build
```

## Project Structure

```
agentwarden/
├── src/
│   ├── index.ts          # Main CLI entry point
│   ├── commands/         # Command implementations
│   │   ├── start.ts      # Start command
│   │   └── status.ts     # Status command
│   └── types/            # TypeScript type definitions
│       └── index.ts      # Type exports
├── package.json          # Package configuration
├── tsconfig.json         # TypeScript configuration
└── README.md            # This file
```

## Tech Stack

- **Runtime**: [Bun](https://bun.sh) - Fast all-in-one JavaScript runtime
- **Language**: TypeScript
- **CLI Framework**: Commander.js
- **Build System**: Bun's built-in bundler
