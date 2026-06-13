# Installers

Shell installers for prebuilt `rastray` binaries. These scripts are also
attached to every GitHub Release so consumers can pipe them directly.

## Unix (Linux / macOS)

```sh
curl -fsSL https://github.com/balangyaoejuspher/rastray/releases/latest/download/install.sh | sh
```

Supported targets:

- `x86_64-unknown-linux-gnu`
- `x86_64-apple-darwin`
- `aarch64-apple-darwin`

Honored environment variables:

| Variable               | Default                     | Meaning                                  |
| ---------------------- | --------------------------- | ---------------------------------------- |
| `RASTRAY_VERSION`      | latest GitHub release       | Install a specific version, e.g. `0.1.0` |
| `RASTRAY_INSTALL_DIR`  | `~/.local/bin`              | Where to drop the binary                 |

## Windows (PowerShell 5.0+)

```powershell
irm https://github.com/balangyaoejuspher/rastray/releases/latest/download/install.ps1 | iex
```

Supported target:

- `x86_64-pc-windows-msvc`

Honored variables / parameters:

| Variable / parameter   | Default                                         |
| ---------------------- | ----------------------------------------------- |
| `$env:RASTRAY_VERSION` | latest GitHub release                           |
| `$env:RASTRAY_INSTALL_DIR` | `%LOCALAPPDATA%\Programs\rastray`           |

You may also invoke the script directly with `-Version` and `-InstallDir`
parameters when running from a local checkout.

## Verification

Both scripts download the matching `.sha256` file from the same GitHub
Release and verify the archive before extraction. The Unix script uses
`sha256sum` or `shasum -a 256`; the Windows script uses `Get-FileHash`.

If the network is unavailable, install from source instead:

```sh
cargo install --git https://github.com/balangyaoejuspher/rastray --locked
```

Or, after the v0.1.0 crates.io publish:

```sh
cargo install rastray --locked
```
