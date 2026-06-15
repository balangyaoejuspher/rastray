# rastray for VS Code

Inline security, dependency, and performance diagnostics
for [rastray](https://github.com/balangyaoejuspher/rastray)
in the Problems panel and as squiggles on save.

## Requirements

- The `rastray` CLI v0.4.0 or newer must be installed and
  on your `PATH` (or pointed to via the `rastray.serverPath`
  setting).
- Install via the prebuilt installer
  (`curl -fsSL https://github.com/balangyaoejuspher/rastray/releases/latest/download/install.sh | sh`)
  or `cargo install rastray --locked`.

## Languages

Activates on Rust, Python, JavaScript / JSX, TypeScript /
TSX, Go, and Java. Each file is scanned on open and on save;
findings appear inline with full per-language remediation
hints.

## Settings

| Setting | Default | Description |
|---|---|---|
| `rastray.serverPath` | `rastray` | Path to the `rastray` executable. |
| `rastray.serverArgs` | `["lsp"]` | Arguments passed when starting the language server. |
| `rastray.trace.server` | `off` | LSP trace verbosity. Output appears in the "rastray" output channel. |

## Commands

| Command | What it does |
|---|---|
| `rastray: Restart Language Server` | Stops the running LSP client and starts a fresh one. Useful after editing `rastray.serverPath`. |

## How it works

The extension is a thin client around the `rastray lsp`
subcommand. The LSP runs in offline mode, scans only the
file that just opened or saved (not the whole workspace),
and reuses the same analyzer registry as the CLI — so a
finding in your editor matches what `rastray` would
print in CI.

## Building from source

```sh
cd editors/vscode
npm install
npm run compile
npm run package   # produces a .vsix you can sideload
```

## License

MIT OR Apache-2.0, same as the rastray repo.
