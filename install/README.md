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

### Cryptographic signatures (cosign)

Starting with v0.1.1, every release archive ships with a matching
`.cosign.bundle` file containing a [Sigstore](https://www.sigstore.dev/)
keyless signature tied to the GitHub Actions workflow that built it.
Verify with [`cosign`](https://github.com/sigstore/cosign):

```sh
cosign verify-blob \
  --bundle rastray-v0.1.1-x86_64-unknown-linux-gnu.tar.gz.cosign.bundle \
  --certificate-identity "https://github.com/balangyaoejuspher/rastray/.github/workflows/release.yml@refs/tags/v0.1.1" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  rastray-v0.1.1-x86_64-unknown-linux-gnu.tar.gz
```

A successful verification confirms the archive was built by this
repository's tagged release workflow and has not been tampered with.

### Offline fallback

If the network is unavailable, install from source instead:

```sh
cargo install --git https://github.com/balangyaoejuspher/rastray --locked
```

Or, after the v0.1.0 crates.io publish:

```sh
cargo install rastray --locked
```
