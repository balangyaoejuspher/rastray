# Distribution manifests

Package-manager manifests for `rastray`. Each file is the source of
truth that gets copied (manually for now, automatically later) into
the corresponding distribution channel.

| file | channel | how end users consume it |
|------|---------|---------------------------|
| `homebrew/rastray.rb` | Homebrew tap | `brew install balangyaoejuspher/rastray/rastray` |
| `scoop/rastray.json`  | Scoop bucket | `scoop bucket add rastray https://github.com/balangyaoejuspher/scoop-rastray; scoop install rastray` |

## Status

- The manifests are **pinned to the current release tag** (`v0.11.0`
  at time of writing). On every new release, the release PR bumps
  the `version`, `url`, and `sha256` / `hash` in both files.
- The Homebrew tap repo (`homebrew-rastray`) and the Scoop bucket
  repo (`scoop-rastray`) are not yet published. Once the manifests
  here have been validated against one or two releases, the same
  files will be mirrored into those repos and the `brew tap` /
  `scoop bucket add` instructions in the main README will start
  pointing at them.

## Refresh procedure (manual)

When cutting a new release:

```sh
# 1. After the release workflow finishes, fetch every SHA256
TAG=v0.12.0
for asset in \
    rastray-${TAG}-aarch64-apple-darwin.tar.gz \
    rastray-${TAG}-x86_64-apple-darwin.tar.gz \
    rastray-${TAG}-x86_64-unknown-linux-gnu.tar.gz \
    rastray-${TAG}-x86_64-pc-windows-msvc.zip
do
    curl -fsSL \
        https://github.com/balangyaoejuspher/rastray/releases/download/${TAG}/${asset}.sha256 \
        | awk '{print $1, "'"$asset"'"}'
done
```

# 2. Update `dist/homebrew/rastray.rb`:
#    - bump `version "0.11.0"` to the new version
#    - replace each `sha256 "..."` with the corresponding hash above

# 3. Update `dist/scoop/rastray.json`:
#    - bump the `"version"` field
#    - replace the `"url"` (rev path) and `"hash"` values

# 4. Commit alongside the version bump as part of the release PR.

## Tested install paths

- macOS Apple Silicon — `brew install --build-from-tarball dist/homebrew/rastray.rb` (smoke-tested before publication)
- Linux x86_64 — same formula, on-linux block exercised in CI matrix
- Windows x86_64 — `scoop install dist/scoop/rastray.json` (manual smoke-test)

## Why not auto-update?

A `release.yml` job that opens a PR to the tap / bucket repos on
every tag push is on the roadmap. Until then, the manual refresh is
two `sed` calls inside the release PR — small enough not to block.
