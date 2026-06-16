# Distribution manifests

Package-manager source-of-truth for `rastray`. The release workflow
mirrors these files into the dedicated tap and bucket repos on every
tag push — no manual SHA-refresh step.

| file | mirrored to | how end users consume it |
|------|-------------|---------------------------|
| `homebrew/rastray.rb` | [balangyaoejuspher/homebrew-rastray](https://github.com/balangyaoejuspher/homebrew-rastray) | `brew install balangyaoejuspher/rastray/rastray` |
| `scoop/rastray.json`  | [balangyaoejuspher/scoop-rastray](https://github.com/balangyaoejuspher/scoop-rastray) | `scoop bucket add rastray https://github.com/balangyaoejuspher/scoop-rastray; scoop install rastray` |

## How the auto-bump works

The `dist-bump` job in
[`.github/workflows/release.yml`](../.github/workflows/release.yml)
runs at the end of every release tag push:

1. Reads the freshly-published `.sha256` files for the four
   release tarballs (`aarch64-apple-darwin`, `x86_64-apple-darwin`,
   `x86_64-unknown-linux-gnu`, `x86_64-pc-windows-msvc`).
2. Rewrites `Formula/rastray.rb` in `homebrew-rastray` with the
   new version + SHAs and pushes the commit.
3. Rewrites `bucket/rastray.json` in `scoop-rastray` the same way
   and pushes the commit.

The job is gated on a `DIST_REPOS_TOKEN` repository secret with
`contents: write` on both downstream repos. If the secret is not
set, the job logs a warning and exits cleanly so the rest of the
release workflow keeps working.

## Why keep the source in `dist/`?

The dedicated tap and bucket repos are mirrors. Keeping the canonical
file in this repo means:

- One PR to bump version / change formula structure / fix a typo —
  the mirrors update automatically on the next tag.
- The diff is easy to review alongside the source change that
  triggered it.
- Existing baselines, link references, and the
  `https://raw.githubusercontent.com/.../dist/...` URLs that some
  early adopters bookmarked all keep working.

## Manual refresh (only if the auto-bump is broken)

```sh
TAG=v0.14.0
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

Then update the `version` and `sha256` fields in
`homebrew/rastray.rb` and `scoop/rastray.json` and commit alongside
the version bump.
