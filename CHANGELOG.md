# Changelog

All notable changes to `rastray` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.15.0] - 2026-06-16

### Added

- **Java rule coverage broadened** with two new patterns covering
  the OWASP-Top-Ten cases that account for most real-world Java
  findings:
  - `RSTR-INJ-012` (`Critical`) \u2014 `Runtime.getRuntime().exec("cmd " + var)`
    or `new ProcessBuilder("cmd " + var)` (single-string form goes
    through the shell; argv-array form is unaffected).
  - `RSTR-NET-005` (`High`) \u2014 a `HostnameVerifier` whose `verify`
    body returns `true` unconditionally (lambda or anonymous-inner-
    class form). Disables TLS hostname binding; MITM-friendly.

  Both run only against Java / Kotlin source files (`.java`, `.kt`,
  `.kts`). Same conservative one-step direct-sink scope as every
  other rastray rule.

  Pre-existing Java coverage continues unchanged: `RSTR-DES-006`
  (ObjectInputStream.readObject), `RSTR-XXE-005` (DocumentBuilderFactory
  / SAXParserFactory / XMLInputFactory), `RSTR-CRY-001` (MD5
  MessageDigest), `RSTR-CRY-002` (SHA-1 MessageDigest).

  2 new unit tests cover the new patterns and their safe-form
  counter-examples (argv-array exec, allow-list verifier).
  2 new docs pages follow the established template; `SUMMARY.md`
  updated.

- **C++ extensions to the memory-safety rule family**: `RSTR-MEM-001`,
  `RSTR-MEM-002`, and `RSTR-INJ-011` now match the `std::`-prefixed
  variants of their target functions (`std::strcpy`, `std::scanf`,
  `std::system`, etc.) in addition to the unqualified C forms.
- **`RSTR-MEM-005` (`Medium`, `Confidence::Low`)** — raw `new T(...)`
  / `new T{...}` / `new T[...]` outside a `std::make_unique` /
  `std::make_shared` wrapper. First built-in rule to opt into
  `Confidence::Low`; surfaces by default so reviewers see the
  pattern, but can be filtered out project-wide with
  `--min-confidence high` once a team has audited their raw-`new`
  sites.

  3 new unit tests cover the `std::`-prefixed forms and the new
  `MEM-005` pattern (including its low-confidence wiring). 1 new
  docs page at `docs/src/rules/RSTR-MEM-005.md` follows the
  established template; `SUMMARY.md` updated.

- **C / C++ memory-safety rule family** broadens analyzer coverage
  to a previously unsupported language pair. Five new rules covering
  the OWASP-Top-25-style memory-safety bug shapes that account for
  the bulk of real-world C / C++ CVE history:
  - `RSTR-MEM-001` (`Critical`) — `strcpy` / `strcat` / `gets` /
    `sprintf` / `vsprintf` (banned, unbounded buffer-overflow
    surface).
  - `RSTR-MEM-002` (`High`) — `scanf` / `fscanf` / `sscanf` (and
    vararg variants) with an unbounded `%s` directive.
  - `RSTR-MEM-003` (`High`) — `alloca(...)` (stack-overflow
    primitive on attacker-controlled size).
  - `RSTR-MEM-004` (`Medium`) — `memcpy` / `memmove` whose length
    is `strlen(...)` without `+ 1` (off-by-one that drops the null
    terminator).
  - `RSTR-INJ-011` (`Critical`) — `system` / `popen` / `execlp` /
    `execvp` / `execve` with a non-string-literal first argument
    (command injection via shell metacharacter parsing).

  All five run only against C/C++ source files (`.c`, `.cc`,
  `.cpp`, `.cxx`, `.h`, `.hpp`, `.hh`, `.hxx`). Same conservative
  one-step direct-sink scope as every other rastray rule — the
  banned function or unsafe argument must appear literally at the
  call site; multi-step taint flow remains out of scope.

  Seven new unit tests cover the patterns and their safe-form
  counter-examples (bounded variants, `fgets`, fixed-size argv,
  string literals). Five new docs pages under `docs/src/rules/`
  follow the established template; `SUMMARY.md` gains a new
  "Memory safety (C / C++)" section.

## [0.14.0] - 2026-06-16

### Added

- **Dedicated Homebrew tap and Scoop bucket repos.** The previously
  in-tree `dist/` files now have proper canonical install paths:
  - macOS / Linux:
    `brew install balangyaoejuspher/rastray/rastray`
    (mirrors `dist/homebrew/rastray.rb` into the
    [balangyaoejuspher/homebrew-rastray](https://github.com/balangyaoejuspher/homebrew-rastray)
    tap)
  - Windows:
    `scoop bucket add rastray https://github.com/balangyaoejuspher/scoop-rastray; scoop install rastray`
    (mirrors `dist/scoop/rastray.json` into the
    [balangyaoejuspher/scoop-rastray](https://github.com/balangyaoejuspher/scoop-rastray)
    bucket)

  Both downstream repos are bumped automatically by a new
  `dist-bump` job in `.github/workflows/release.yml` that runs at
  the end of every release tag push. The job reads the four
  per-tarball `.sha256` files from the GitHub release, rewrites the
  formula and the manifest with the new version + hashes, and
  pushes the commit to each repo. Gated on a `DIST_REPOS_TOKEN`
  repository secret; if the secret is missing the job warns and
  exits cleanly so the rest of the release workflow keeps working.

  README "Installation" section's Homebrew and Scoop subsections now
  document the actual `brew install` / `scoop bucket add` commands
  (replacing the previous "tap repository will be published soon"
  placeholder). `dist/README.md` documents the auto-bump flow plus
  a manual-refresh fallback procedure.

  In-tree `dist/homebrew/rastray.rb` and `dist/scoop/rastray.json`
  are bumped to v0.13.0 in this PR; future tags update them via
  the workflow.

- **`rastray install-hooks` subcommand** wires a tiny POSIX-shell
  pre-commit hook into the current repo and points
  `git config core.hooksPath` at it in one step. The script runs
  `rastray --changed-only --fail-on high` on every commit (blocks
  only on High or Critical findings in the staged diff) and exits
  with a clear message if the `rastray` binary is missing from
  `PATH`. Pass `--force` to overwrite an existing hook; without it
  the subcommand refuses to clobber whatever is already there. README
  gains a new "Native git hook (no framework)" section under
  Continuous integration with the one-line install snippet, sitting
  next to the existing `pre-commit` framework integration so users
  can pick the workflow that matches their team.

### Changed

- README pre-commit framework example now pins `rev: v0.13.0` (was
  `v0.11.0`, stale by two releases). Existing consumers using
  `pre-commit autoupdate` were unaffected; consumers who copy-pasted
  the README snippet now get the latest existing tag on first install.

## [0.13.0] - 2026-06-16

### Added

- **Container image scanning** via a new `rastray image <archive>`
  subcommand. Accepts a `docker save` tarball or an OCI image
  layout exported to a tarball (no registry pull, no docker daemon
  required). Walks every layer, recursively unpacks nested `.tar` /
  `.tar.gz` / `.tgz` entries up to four levels deep, and runs the
  secrets analyzer against every text file inside. Binary files
  and files larger than `--max-file-bytes` (default 4 MiB) are
  skipped. Findings render with a synthetic location like
  `image.tar::sha256.../layer.tar::etc/leaked.env` so reviewers
  can tell exactly which layer the leak lives in.

  Two new dependencies: `tar = 0.4` and `flate2 = 1.0` (rust-only
  backend, no `libz-sys`). The scanner reuses the same
  `scan_text_for_secrets` helper introduced for git-history sweeps,
  so the pattern set, entropy thresholds, and rule codes all
  match a working-tree scan exactly.

  Scope note: this is intentionally **not** a CVE scanner for OS
  packages (no `dpkg`/`rpm`/`apk` database parsing, no
  vulnerability DB). Run `trivy image` alongside for OS-package
  CVE coverage — the two tools cover non-overlapping concerns.

  4 new unit tests cover the inner-tar detection, binary-file
  heuristic, and gzip pass-through. 1 new integration test
  hand-builds a two-level nested tarball with an AWS key inside
  and asserts the scan flags it.

- **Git-history secret sweep** via a new `rastray secrets --history`
  subcommand. Walks every commit in the repository (optionally
  filtered with `--since <ref>` or capped with `--max-commits N`),
  enumerates each commit's added or modified files via
  `git diff-tree`, and runs the secrets analyzer's pattern set
  against every historical blob. Findings render with a synthetic
  location like `path/to/file.env@abcdef1` so reviewers can
  `git show abcdef1:path/to/file.env` directly to inspect the
  historical blob.

  The scanner shells out to `git` (the same approach `--since` /
  `--changed-only` already use) — no new dependency added. The
  secrets pattern set is reused verbatim via a new public
  `scan_text_for_secrets(contents, synthetic_path)` helper on the
  secrets analyzer.

  Findings honour the same `--min-severity` / `--min-confidence` /
  `--json` / `--format` flags as a working-tree scan. Exit code is
  `0` for zero findings, `1` otherwise.

  3 new unit tests cover the SHA truncation and synthetic-path
  helpers; 1 new integration test spins up a tiny git repo, commits
  an AWS key, `git rm`s it, commits again, and asserts the history
  scan still flags the leaked blob.

- **Per-finding `confidence` field** with three values (`low`,
  `medium`, `high`). Every existing rule defaults to `high` — there
  is no behaviour change for any current scan. New (typically
  heuristic) rules can opt into lower confidence via the
  `Finding::with_confidence(...)` builder; those findings can then
  be filtered out at the report boundary with the new
  `--min-confidence <LEVEL>` CLI flag (default `low`, accepts
  `low` / `medium` / `high`). Human-readable output appends
  `(confidence: med|low)` to the help line whenever the finding's
  confidence is below `high`, so reviewers can tell heuristic from
  exact-match findings at a glance. JSON output gains a `confidence`
  field on every finding (automatic via serde); SARIF results gain
  a `properties.confidence` slot (where the SARIF spec permits open
  extensions). The LSP preserves the default behaviour
  (`Confidence::Low` minimum, i.e. show everything).

  Five new unit tests cover the filter and ordering semantics.

## [0.12.0] - 2026-06-16

### Added

- **Kubernetes and Terraform rule coverage** broadens the IaC analyzer
  from Dockerfile-only to three file types. Five new rules:
  - `RSTR-IAC-007` (`High`) — Kubernetes container with
    `securityContext.privileged: true`. Detected in any PodSpec-
    bearing kind (`Pod`, `Deployment`, `StatefulSet`, `DaemonSet`,
    `Job`, `CronJob`, `ReplicaSet`, `ReplicationController`).
  - `RSTR-IAC-008` (`High`) — PodSpec sets `hostNetwork: true` /
    `hostPID: true` / `hostIPC: true` (collapses the container/host
    isolation boundary).
  - `RSTR-IAC-009` (`High`) — Terraform `aws_s3_bucket` with
    `acl = "public-read"` or `"public-read-write"`.
  - `RSTR-IAC-010` (`Critical`) — Terraform security-group rule
    with `cidr_blocks = ["0.0.0.0/0"]`.
  - `RSTR-IAC-011` (`High`) — Terraform `aws_db_instance` /
    `aws_rds_cluster_instance` with `publicly_accessible = true`.

  Kubernetes manifests are detected by the combination of a `.yaml` /
  `.yml` extension and a workload-bearing `kind:` near the top of the
  file (Pod, Deployment, etc.) — plain ConfigMaps and unrelated YAML
  files are not flagged. Terraform is detected by the `.tf` and
  `.tfvars` extensions, both newly added to the crawler's config-file
  list.

  Eight new unit tests cover the new patterns and their safe-form
  counter-examples. Five new docs pages follow the established
  template.

- **Built-in fixture-noise filter** for the two secret-scanning rules
  most prone to false positives on real codebases when intentional
  test fixtures hold sample PEM blocks or API-key snippets:
  `RSTR-SEC-007` and `RSTR-SEC-006`. Findings for those codes are now
  silently dropped when the file path contains any of the common
  test-fixture segments (`tests`, `test`, `unittests`, `unittest`,
  `spec`, `specs`, `__tests__`, `fixtures`, `fixture`, `samples`,
  `sample`, `examples`, `example`, `testdata`, `test-fixtures`,
  `test_fixtures`). The new `--no-default-skip` flag opts out of
  this filter when needed.

  Calibration: on the django-DefectDojo benchmark, the filter brings
  the fresh-adoption finding count from 1 221 to 715 (-41%) with no
  reduction in coverage of source code. Every dropped finding is one
  rastray *would* have flagged before; the dropped ones are
  overwhelmingly intentional fixtures.

- **Homebrew formula** at `dist/homebrew/rastray.rb` and **Scoop
  manifest** at `dist/scoop/rastray.json`, both pinned to the
  current release tag and downloading the same checksum-verified
  release tarballs the shell installer uses. README "Installation"
  section gains new Homebrew and Scoop sub-sections with direct-
  install snippets that work today; dedicated tap / bucket repos
  are queued as a follow-up. `dist/README.md` documents the layout
  and the manual SHA-refresh procedure that the release PR runs.

- **Docs Quickstart page** at `docs/src/quickstart.md` consolidating
  install (installer, cargo, Windows ps1), smoke-test, pre-commit
  integration, GitHub Actions integration, and editor (LSP) wiring
  into one two-minute path. Linked from `SUMMARY.md` between the
  Introduction and the "How to read these pages" guide.

### Changed

- README pre-commit example now pins `rev: v0.11.0` (was `v0.4.0`,
  badly stale). Existing consumers using `pre-commit autoupdate`
  were unaffected; consumers who copy-pasted the README snippet now
  get a real existing tag on first install.

## [0.11.0] - 2026-06-16

### Added

- **Ruby (Rails) rule coverage broadened** with five new direct-sink
  patterns covering the OWASP-Top-Ten cases that account for most
  real-world Rails findings:
  - `RSTR-INJ-008` (`Critical`) — Rails ActiveRecord `.where` /
    `.find_by_sql` / `.update_all` / `.delete_all` etc. called with
    a string-interpolated SQL fragment that contains `params[...]`.
  - `RSTR-INJ-009` (`High`) — `params[:x].constantize` /
    `.safe_constantize` / `.classify` (arbitrary class instantiation
    from request input).
  - `RSTR-INJ-010` (`Critical`) — Rails `render inline:` / `text:`
    with `#{params[...]}` interpolation (server-side template
    injection).
  - `RSTR-ORM-005` (`High`) — `params.require(:x).permit!`
    (open-permit form of Strong Parameters).
  - `RSTR-RDR-004` (`Medium`) — `redirect_to params[...]`
    (open-redirect).

  All five are direct-sink matches; the request value must appear in
  the same call/expression. Same conservative one-step taint scope as
  every other rastray rule.

  Seven new unit tests cover the patterns and their safe-form
  counter-examples. Five new docs pages follow the established
  template. The RailsGoat benchmark page is refreshed: rastray
  findings on RailsGoat grew from 6 to 11 (almost 2x).

## [0.10.0] - 2026-06-15

### Added

- **PHP rule coverage broadened** with five new direct-superglobal
  patterns covering the OWASP-Top-Ten cases that account for most
  real-world PHP findings:
  - `RSTR-INJ-006` (`Critical`) — SQL injection via `mysqli_query` /
    `pg_query` / `$pdo->query()` with `$_GET[...]` / `$_POST[...]` /
    `$_REQUEST[...]` interpolated.
  - `RSTR-INJ-007` (`Critical`) — command exec via `exec` / `system` /
    `shell_exec` / `passthru` / backticks on a request superglobal.
  - `RSTR-XSS-006` (`High`) — `echo` / `print` / short-echo `<?=`
    of a request superglobal without `htmlspecialchars`.
  - `RSTR-PTH-005` (`Critical`) — `include` / `require` / `_once`
    with a request superglobal (LFI / RFI).
  - `RSTR-PTH-006` (`High`) — `file_get_contents` / `fopen` /
    `readfile` / `file_put_contents` with a request superglobal.

  All five are direct-sink matches — the superglobal must appear in
  the same call expression. The conservative one-step taint scope
  is consistent with the rest of rastray; multi-step flow remains
  out of scope.

  Eight new unit tests cover the patterns and the
  `htmlspecialchars`-wrapped negative case. Five new docs pages
  follow the established template (Summary / Severity / Languages /
  What rastray flags / What rastray deliberately does *not* flag /
  How to fix / References).

  The DVWA benchmark page is updated to explain that DVWA's
  pedagogical assign-then-use idiom does not trigger the new
  rules, and to demonstrate the direct-sink pattern they do catch.

## [0.9.0] - 2026-06-15

### Added

- **Benchmark chapter** on the docs site comparing rastray against
  Semgrep, bandit, gosec, gitleaks, and eslint-plugin-security
  across six known-vulnerable codebases (OWASP Juice Shop, NodeGoat,
  DVWA, RailsGoat, WebGoat, django-DefectDojo). Methodology page,
  consolidated summary, and per-target breakdowns live under
  `docs/src/benchmarks/`; a top-level `BENCHMARKS.md` summarises and
  links to the site.
- **Reproducible benchmark harness** at
  `scripts/benchmarks/run.ps1`. Runs every applicable tool against
  every target, normalises results to a common schema, and writes
  per-tool JSON outputs plus a consolidated `summary.json`.

## [0.8.0] - 2026-06-15

### Added

- **Per-rule documentation site fully completed.** Every shipping
  rule code now has a dedicated page following the same template
  (Summary, Severity, Languages, What rastray flags, What rastray
  deliberately does *not* flag, How to fix, References). The site
  grew from 21 pages to 93 — the docs now cover the full catalogue
  including the secrets family (`RSTR-SEC-002..008`), the broken-crypto
  variants (`RSTR-CRY-003..007`), the deserialization family
  (`RSTR-DES-001..007`), the path-traversal family
  (`RSTR-PTH-001..004`), the injection variants
  (`RSTR-INJ-002..005`), JWT misuse cases (`RSTR-JWT-002, 003, 005`),
  the SSRF/XSS/XXE/RDR/SSTI/NOSQLI variants in each language family,
  the cookie/CORS/CSRF web-app cluster, the ORM mass-assignment
  variants (`RSTR-ORM-002, 003`), `RSTR-LDAP-002`, the network
  family (`RSTR-NET-002..004`), the GHA family
  (`RSTR-GHA-001, 002, 003, 005`), the Docker / IaC family
  (`RSTR-IAC-001, 002, 003, 005, 006`), and every performance rule
  (`RSTR-PERF-001, 002, 101, 102, 201, 202, 301, 302`). `SUMMARY.md`
  reorganised into 17 topic-aligned chapters.

### Changed

- README now characterises CodeQL accurately: it is free for
  open-source projects (paid via GitHub Advanced Security only for
  closed-source / commercial use). Semgrep is described as free OSS
  with a paid Pro tier.

### Dependencies

- `toml` 0.8 → 1.1 (the 1.x release moved `from_str`, `from_slice`,
  and `Deserializer` behind the `serde` feature; rastray's manifest
  now opts in to the feature).
- `tree-sitter-javascript` 0.23 → 0.25.
- `tree-sitter-python` 0.23 → 0.25.
- `tree-sitter-go` 0.23 → 0.25.

## [0.7.0] - 2026-06-15

### Added

- **Custom regex rules** via `[[custom_rule]]` blocks in
  `.rastray.toml`. Teams can ship project-specific checks
  without forking the analyzer:

  ```toml
  [[custom_rule]]
  id          = "ACME-001"
  pattern     = '\bTODO\(security\)\b'
  message     = "security TODO marker found"
  severity    = "medium"
  help        = "resolve the TODO before merging"
  extensions  = ["rs", "py"]
  ```

  Each entry requires `id`, `pattern` (Rust regex), and
  `message`. Optional `severity` (`info`/`low`/`medium`/
  `high`/`critical`, default `medium`), `help` text, and
  `extensions` filter. Loader validates non-empty
  required fields, regex compilability, and severity
  spelling at config load time and reports the offending
  rule by id. Custom-rule findings flow through the same
  baseline, suppression, severity remap, autofix exclusion,
  and CI-gating pipeline as built-in rules.

- **Per-rule documentation site** at
  [balangyaoejuspher.github.io/rastray](https://balangyaoejuspher.github.io/rastray/).
  Built with mdBook from `docs/src/`, automatically
  rebuilt and deployed on every push to `main` via a new
  `docs` GitHub Actions workflow that uploads the artifact
  via `actions/upload-pages-artifact` and deploys with
  `actions/deploy-pages`.

  Each rule page follows a consistent template: summary,
  severity, supported languages, what rastray flags
  (with true-positive example), what it deliberately does
  not flag (with discriminator examples), canonical
  remediation, suppression syntax, and CWE / OWASP /
  vendor-doc references.

  This release ships fully-elaborated pages for the rules
  most commonly seen in real reports
  (`RSTR-SSRF-001`, `RSTR-CRY-001`, `RSTR-CRY-002`,
  `RSTR-INJ-001`, `RSTR-XSS-001`, `RSTR-XSS-002`,
  `RSTR-JWT-001`, `RSTR-JWT-004`, `RSTR-RDR-001`,
  `RSTR-SSTI-001`, `RSTR-XXE-001`, `RSTR-NOSQLI-001`,
  `RSTR-NOSQLI-002`, `RSTR-CORS-001`, `RSTR-CSRF-001`,
  `RSTR-ORM-001`, `RSTR-ORM-004`, `RSTR-LDAP-001`,
  `RSTR-REDOS-001`, `RSTR-NET-001`, `RSTR-SEC-001`).
  Remaining rule codes will land per-PR using the same
  template.

  README updated to link the docs site in the "Rule
  families" section. `docs/book/` added to `.gitignore`
  (regenerated by CI).

## [0.6.0] - 2026-06-15

### Added

- **LDAP-injection analyzer** (`RSTR-LDAP-*`) — two new
  rule codes catching the most common LDAP-filter injection
  pattern: a JS template literal or Python f-string used as
  the LDAP filter argument.
  - `RSTR-LDAP-001` (`High`) — Node `client.search(..., { filter: \`(uid=${u})\` })` or `client.search(\`(uid=${u})\`)` with template-literal interpolation.
  - `RSTR-LDAP-002` (`High`) — Python `conn.search(..., f'(uid={user})')` / `conn.search_s(..., scope, f'(uid={user})')` with f-string interpolation.

  Help text spells out the canonical escape:
  `ldap-escape.filter(...)` for Node, `ldap3.utils.conv.escape_filter_chars(...)`
  for Python; better still, use `ldapjs.parseFilter` to
  build the filter from a structured object instead of a
  string. Discriminator tests prove literal-string filters
  (`'(objectClass=person)'`) are not flagged.

- **ReDoS analyzer** (`RSTR-REDOS-001`, `High`) — flags
  regex literals and `new RegExp(...)` / `re.compile(...)`
  patterns containing a nested quantifier of the form
  `(X+)+`, `(X*)+`, `(X+)*`, or similar — the textbook
  catastrophic-backtracking shape that runs in exponential
  time on inputs like `aaaa...aab`.

  Covers JS regex literals (`/...../flags`), JS `new RegExp(...)`,
  and Python `re.compile/match/search/fullmatch/findall/finditer/sub`.

  Help text gives the canonical rewrite: atomic group /
  possessive quantifier / character class
  (`(a+)+` → `a+`, `(?:[ab])+` instead of `(a|b)+`), and
  recommends a linear-time regex engine (RE2, `re2-wasm`,
  Rust's `regex` crate) for any pattern that touches user
  input. Discriminator tests prove simple `a+`, `[a-z]+`,
  etc. are not flagged.

- **ORM mass-assignment + raw-SQL analyzer** (`RSTR-ORM-*`)
  — four new rule codes covering the dominant ORM bug
  classes across Node, Python (Django), and Ruby (Rails):
  - `RSTR-ORM-001` (`High`) — Node ORM `Model.create(req.body)`
    / `Model.update(req.body, ...)` / Prisma
    `prisma.x.create({ data: req.body })`. Mass-assignment:
    any field name in the request (e.g. `isAdmin`, `role`,
    `verified`) gets written even if it wasn't in the form.
  - `RSTR-ORM-002` (`High`) — Django
    `Model.objects.create(**request.POST)` /
    `filter(**request.data)` etc. Same mass-assignment
    pattern in Python.
  - `RSTR-ORM-003` (`High`) — Rails
    `Model.update(params[:user])` / `Model.create(params[:x])`
    without `params.require(...).permit(...)`. Strong
    Parameters bypass.
  - `RSTR-ORM-004` (`Critical`) — Node raw SQL with template
    literals: `knex.raw(\`SELECT ... WHERE id = ${id}\`)`,
    `sequelize.query(\`...${x}...\`)`, Prisma
    `$queryRawUnsafe(\`...${x}...\`)`. Critical because it
    is direct SQL injection.

  Same captured-call-site message convention as the rest of
  the security-analyzer family. Help text per ORM ecosystem
  gives the canonical safe form: `lodash.pick(req.body,
  ['name', 'email'])` for Node, `pydantic` / `ModelForm`
  for Django, `params.require(:user).permit(...)` for
  Rails, parameter binding (`?`) for raw SQL.

  Discriminator tests prove the safe forms are NOT flagged:
  `User.create(_.pick(req.body, ['name', 'email']))`,
  `User.objects.create(name=name, email=email)` (explicit
  kwargs), `@user.update(params.require(:user).permit(:name,
  :email))`, `knex.raw('SELECT * WHERE id = ?', [id])`,
  and template literals **without** `${}` interpolation.

- **JWT-misuse analyzer** (`RSTR-JWT-*`) — five new rule
  codes catching the most common JSON-Web-Token bugs across
  Node (`jsonwebtoken`), Python (`pyjwt`), and Go
  (`github.com/golang-jwt/jwt`):
  - `RSTR-JWT-001` (`Critical`) — accepts `alg: 'none'` or the
    wildcard `algorithms: ['*']`. JS/TS + Python. Bypasses
    signature verification entirely.
  - `RSTR-JWT-002` (`Critical`) — skips signature verification
    via `jwt.decode(token, { verify: false })` (JS),
    `verify_signature: False` in `options` (Python), or
    `verify=False` keyword (Python).
  - `RSTR-JWT-003` (`High`) — hardcoded HMAC secret string
    literal in `jwt.sign(...)` / `jwt.encode(...)`.
  - `RSTR-JWT-004` (`High`) — `jwt.verify(token, secret)` /
    `jwt.decode(token, key)` without an explicit
    `algorithms` list — enables alg-confusion attacks
    (forge an HS256 token using the RS256 public key).
  - `RSTR-JWT-005` (`High`) — Go `jwt.Parse(t, func(...))`
    whose keyfunc returns a secret without first checking
    `token.Method.(*jwt.SigningMethodHMAC)`.

  Same captured-call-site message convention as the rest of
  the security-analyzer family. Help text per language
  ships the hardened form: explicit `algorithms` list
  (`['RS256']`), secret loaded from `process.env` /
  `os.environ` / `os.Getenv`, and for Go the
  `if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok`
  guard inside the keyfunc.

  Discriminator tests prove the safe forms are not flagged:
  `algorithms: ['RS256']` explicit list,
  `algorithms=['RS256']` in Python, and
  `process.env.JWT_SECRET` instead of a literal.

- **Web-app config analyzer** (`RSTR-COOKIE-*`, `RSTR-CORS-*`,
  `RSTR-CSRF-*`) — eight new rule codes catching the most
  common misconfiguration bugs in web stacks:

  Session cookies (`RSTR-COOKIE-*`):
  - `RSTR-COOKIE-001` (High) — `cookie: { ..., secure: false, ... }` in JS/TS.
  - `RSTR-COOKIE-002` (High) — `cookie: { ..., httpOnly: false, ... }` in JS/TS.
  - `RSTR-COOKIE-003` (Medium) — `sameSite: 'none'` (the cross-site-CSRF-enabler) in JS/TS.

  CORS (`RSTR-CORS-*`):
  - `RSTR-CORS-001` (High) — `cors({ origin: true | '*', credentials: true })` in either argument order. The browser collapses `origin: true` to the request's `Origin` header and then accepts credentials from anywhere; same-origin policy is bypassed.
  - `RSTR-CORS-002` (High) — raw `setHeader('Access-Control-Allow-Origin', '*')` literal in JS/TS.

  CSRF (`RSTR-CSRF-*`):
  - `RSTR-CSRF-001` (High) — `WTF_CSRF_ENABLED = False` (bare assignment **or** `app.config['WTF_CSRF_ENABLED'] = False`) in Python.
  - `RSTR-CSRF-002` (Medium) — `@csrf_exempt` decorator on a Django view.

  Same captured-call-site message convention as the other
  Phase-10 analyzer families. Help text per family gives
  the canonical hardened form (allow-list of trusted
  origins for CORS; `{{ csrf_token() }}` in every form for
  Flask-WTF; `@csrf_exempt` only with signed-webhook
  verification for Django).

  Discriminator tests prove the safe forms are not flagged:
  hardened cookies (`secure: true, httpOnly: true,
  sameSite: 'strict'`); CORS with explicit
  allow-list + credentials; CORS wildcard *without*
  credentials (the safe public-API case);
  `WTF_CSRF_ENABLED = True`; `sameSite: 'strict'`.

  Multi-step taint flow and config-object indirection are
  out of scope — same boundary as the other Phase-10
  analyzers.

- **`--fix` mode** — opt-in safe-substitution auto-fix for
  a curated set of rules that have a 1:1 mechanical
  remediation. `rastray --fix` (no apply) prints a unified
  diff of every planned change without touching the
  filesystem; `rastray --fix --yes` writes the changes
  back to disk and prints `fixed` lines per substitution.
  Findings without a registered fixer (i.e. the SSRF / XSS
  / SSTI / XXE / NoSQLi / open-redirect families and most
  other rules) are silently skipped — auto-fix is
  deliberately limited to fixes that can be done safely
  with a single line-level string substitution.

  Initial fixer set (more can land per-rule without an
  architecture change):

  - `RSTR-DES-002` (Python) — `yaml.load(` → `yaml.safe_load(`
  - `RSTR-CRY-001` — MD5 hash construction → SHA-256
    across Python (`hashlib.md5`), Node
    (`crypto.createHash('md5')` / `"md5"`), Java
    (`MessageDigest.getInstance("MD5"`), and Go
    (`md5.New()`, `"crypto/md5"` imports)
  - `RSTR-CRY-002` — SHA-1 hash construction → SHA-256
    across the same four ecosystems
    (`hashlib.sha1`, `createHash('sha1')`,
    `MessageDigest.getInstance("SHA-1"` and `"SHA1"`,
    `sha1.New()`, `"crypto/sha1"` imports)

  Rules that need multi-line refactoring (`verify=False`
  removal, `Math.random()` replacement,
  `actions/checkout@v4` SHA pinning) are deliberately not
  in this slice — they require parsing the surrounding
  call to keep argument lists / variable references
  correct, which is taint-analysis territory and out of
  scope. Add them later, one per follow-up slice, only
  once we have an AST rewriter that can guarantee the
  result still compiles.

  CLI flags are mutually compatible with all existing
  ones — `--fix` works alongside `--since`, `--baseline`,
  `--include-minified`, etc. — and short-circuits the
  normal report rendering: when `--fix` is on, only the
  preview / applied lines are printed.

## [0.5.0] - 2026-06-15

### Added

- **VS Code extension** under [`editors/vscode/`](editors/vscode/).
  Thin client around `rastray lsp` written in TypeScript
  against `vscode-languageclient ^9.0.1`. Activates on
  Rust, Python, JavaScript / JSX, TypeScript / TSX, Go, and
  Java files; spawns `rastray lsp` over stdio and forwards
  diagnostics into the Problems panel. Three settings
  (`rastray.serverPath`, `rastray.serverArgs`,
  `rastray.trace.server`) and one command
  (`rastray: Restart Language Server`). A `vscode extension
  build` job in CI runs `tsc` + `vsce package` on every PR
  and uploads the resulting `.vsix` as an artifact. No
  marketplace publish yet — sideload via the artifact or
  build locally with `npm install && npm run package`.

- **`rastray lsp` subcommand** — built-in Language Server
  Protocol implementation over stdio so findings surface
  inline in any LSP-aware editor (VS Code, Neovim, Helix,
  Zed, Emacs) as you save a file. Each `textDocument/didOpen`
  and `textDocument/didSave` triggers an in-process scan of
  the single file through the existing analyzer registry,
  then emits one `textDocument/publishDiagnostics`. Each
  diagnostic carries the `RSTR-<FAMILY>-<NNN>` rule code,
  the captured-call-site message, severity mapped to LSP
  (`Critical`/`High` → Error, `Medium` → Warning, `Low` →
  Information, `Info` → Hint), and the per-language
  remediation help text in `relatedInformation`.

  The LSP runs in offline mode (no OSV.dev calls), uses a
  single worker thread, and only scans the file that just
  opened or saved — not the whole workspace — keeping
  latency under 100 ms on typical files. Wire-up snippets
  for Neovim (`nvim-lspconfig`) and Helix (`languages.toml`)
  are in the README under "Editor integration (LSP)".

  Powered by `tower-lsp 0.20` over `tokio` stdio. The
  existing `Analyzer` trait is reused verbatim — no
  analyzer code paths changed.

## [0.4.0] - 2026-06-14

### Added

- **SSRF analyzer** (`RSTR-SSRF-*`) for HTTP-request sinks
  that consume request input directly. Catches common
  server-side request forgery shapes:
  - `RSTR-SSRF-001` — JS/TS `fetch(req.body.url)`,
    `axios.get(req.query.next)`, `axios.post(req.params.x)`,
    etc.
  - `RSTR-SSRF-002` — JS/TS `http.get(req.body.url)`,
    `https.request(req.query.x)`.
  - `RSTR-SSRF-003` — Python `requests.get(request.args.get('u'))`,
    `urllib.request.urlopen(request.form['url'])`, etc.
  - `RSTR-SSRF-004` — Go `http.Get(r.FormValue("url"))`,
    `http.NewRequest(_, r.URL.Query().Get("u"), _)`.

  All four are `high` severity. The finding message
  **interpolates the actual matched call site**
  (e.g. ``RSTR-SSRF-001: `fetch(req.body.url)` issues an HTTP request to a URL taken from request input — SSRF risk``)
  so every finding line in a report is distinguishable at a
  glance, not "200 copies of the same generic warning".
  Help text is per-language: JS gets the
  ``new URL(input).hostname`` allow-list idiom; Python and
  Go get language-specific guidance including blocking
  cloud-metadata addresses.

- **XSS analyzer** covering reflected and DOM-based XSS
  across JavaScript / TypeScript, Python (Flask), and Go
  (net/http). Five new rule codes, all `High` severity:
  - `RSTR-XSS-001` — Express `res.send` / `res.end` /
    `res.write` with `req.body.*` / `req.query.*` /
    `req.params.*` / `req.cookies.*` / `req.headers.*`.
  - `RSTR-XSS-002` — `.innerHTML` / `.outerHTML` assigned
    from `location.*`, `window.name`, `document.URL`,
    `document.cookie`, `document.referrer`, `document.baseURI`,
    `document.documentURI`.
  - `RSTR-XSS-003` — `document.write(...)` / `document.writeln(...)`
    with the same DOM sources.
  - `RSTR-XSS-004` — Python Flask: `return request.args.get(...)`
    / `return request.form[...]` directly returned as the
    response body, or `Markup(request.x)` wrapping user
    input.
  - `RSTR-XSS-005` — Go: `fmt.Fprintf(w, ...)` / `fmt.Fprint`
    / `fmt.Fprintln` / `io.WriteString(w, ...)` with
    `r.FormValue(...)` / `r.URL.Query().Get(...)` /
    `r.PostFormValue(...)`.

  Each finding uses the captured-call-site message format,
  so 200 findings produce 200 distinguishable lines instead
  of 200 copies of the same warning. Help text gives an
  idiomatic remediation per language (DOMPurify / `.textContent`
  for JS DOM, `res.json(...)` / `he.encode(...)` for JS
  reflected, `markupsafe.escape(...)` / Jinja2 autoescape for
  Python, `html.EscapeString(...)` / `html/template` for Go).

  Multi-step taint flow is deliberately out of scope — the
  pattern requires the user-controlled expression to appear
  directly in the sink call. Use CodeQL or Semgrep Pro for
  full taint analysis.

- **Open-Redirect analyzer** covering Express, Flask, Django,
  and Go (net/http). Three new rule codes, all `Medium`
  severity (open redirect is real but lower-blast-radius
  than SSRF/XSS — it powers phishing, not direct code
  execution):
  - `RSTR-RDR-001` — Express `res.redirect(req.body.*)` /
    `res.redirect(req.query.*)` / `res.redirect(req.params.*)`
    (also matches the status-code form `res.redirect(302, req.body.url)`).
  - `RSTR-RDR-002` — Flask `redirect(request.args.get(...))`
    / `redirect(request.form[...])` and Django
    `HttpResponseRedirect(request.GET.get(...))` /
    `HttpResponseRedirect(request.POST[...])`.
  - `RSTR-RDR-003` — Go `http.Redirect(w, r, r.FormValue(...), 302)`
    / `http.Redirect(w, r, r.URL.Query().Get(...), 302)`.

  Same captured-call-site message convention as
  `RSTR-SSRF-*` and `RSTR-XSS-*`. Help text gives the
  idiomatic remediation per framework: allow-list of
  known-safe paths for JS; `url_has_allowed_host_and_scheme`
  for Django, `urllib.parse.urlparse` + `netloc` check for
  Flask; allow-list before `http.Redirect` for Go.

  Multi-step taint flow (intermediate-variable redirects) is
  deliberately out of scope.

- **SSTI (Server-Side Template Injection) analyzer**
  covering Jinja2 / Flask and the major Node template
  engines. Two new rule codes, both `High` severity (SSTI
  routinely escalates to remote code execution through
  template-engine sandbox escapes — search "Flask SSTI RCE"
  / "Handlebars prototype pollution to RCE"):
  - `RSTR-SSTI-001` — Python: `Template(request.x)`,
    `jinja2.Template(request.x)`, `render_template_string(request.x)`,
    `env.from_string(request.x)`.
  - `RSTR-SSTI-002` — JS / TS: `pug.render(req.x)`,
    `pug.compile(req.x)`, `Handlebars.compile(req.x)`,
    `ejs.render(req.x)`, `nunjucks.renderString(req.x)`,
    `Mustache.render(req.x)`.

  Same captured-call-site message convention as
  `RSTR-SSRF-*`, `RSTR-XSS-*`, and `RSTR-RDR-*`. Help text
  emphasizes the correct pattern: load templates from disk
  by name and pass user input as **data**, never as the
  template body itself. `render_template('home.html', name=user)`
  is safe; `render_template_string(user_supplied_source)`
  is the bug.

  Multi-step taint flow (intermediate-variable templates)
  is deliberately out of scope; the `intermediate_variable_is_not_flagged`
  test documents this explicitly.

- **XXE (XML External Entity) analyzer** covering Python
  (stdlib `xml.etree` / `xml.sax` / `xml.dom.minidom` and
  lxml), Node (`libxmljs` with `noent: true`, `xml2js`),
  and Java (`DocumentBuilderFactory`, `SAXParserFactory`,
  `XMLInputFactory`). Five new rule codes; most are
  `High` severity (XXE → local-file disclosure and SSRF
  via `file://` and `http://` entity URIs, occasionally
  RCE), one is `Medium` (`RSTR-XXE-004` for `xml2js` —
  config-level, less direct).
  - `RSTR-XXE-001` — Python stdlib XML APIs without
    `defusedxml`.
  - `RSTR-XXE-002` — `lxml.etree.XMLParser(resolve_entities=True)`.
  - `RSTR-XXE-003` — `libxmljs.parseXml(..., {noent: true})`.
  - `RSTR-XXE-004` — `xml2js.Parser(...).parseString(input, cb)`.
  - `RSTR-XXE-005` — Java `DocumentBuilderFactory.newInstance()` /
    `SAXParserFactory.newInstance()` /
    `XMLInputFactory.newInstance()` without the documented
    feature flags that disable DOCTYPE and entity expansion.

  Same captured-call-site message convention as the other
  analyzers. Help text includes the exact remediation
  snippet: `defusedxml.ElementTree.fromstring(...)` for
  Python stdlib; `XMLParser(resolve_entities=False, no_network=True, load_dtd=False)`
  for lxml; remove `noent: true` for libxmljs; the
  full OWASP-recommended `setFeature(...)` quartet for
  Java factories.

  The Java rules deliberately flag the factory-construction
  site rather than the parse call, because XXE in Java is
  controlled by the factory's feature configuration — not
  by how the parser is later invoked. A flagged
  `newInstance()` is a TODO to apply the hardened
  configuration; the help text spells out the exact
  snippet.

- Note on `xml.etree` deprecation: Python's docs explicitly
  warn that stdlib XML parsers are "not secure against
  maliciously constructed data" and recommend `defusedxml`.
  This analyzer treats any usage on untrusted input as a
  bug regardless of Python version.

- **NoSQL-injection analyzer** covering MongoDB-style
  operator-injection bugs in Node and Python. Three new
  rule codes:
  - `RSTR-NOSQLI-001` (`High`) — Node: `.find` / `.findOne`
    / `.updateOne` / `.deleteOne` / `.countDocuments` (full
    list) with `{ key: req.body.x }` / `{ key: req.query.x }`
    / etc. An attacker submitting `{ "$gt": "" }` as the
    JSON body instead of a string bypasses the filter and
    returns every document.
  - `RSTR-NOSQLI-002` (`Critical`) — Node: `$where`
    populated from a template literal interpolating
    request input, or `$where` set directly to request
    input. `$where` evaluates server-side JavaScript in the
    Mongo process — this is a direct remote-code-execution
    sink and earns Critical.
  - `RSTR-NOSQLI-003` (`High`) — Python: pymongo
    `.find` / `.find_one` / `.update_one` etc. with
    `{"key": request.json['x']}` /
    `{"key": request.args.get('x')}`.

  All three follow the captured-call-site message
  convention. Help text gives the exact remediation idiom:
  `String(req.body.user)` / `Number(req.body.id)` coercion
  for JS; `str(request.json['user'])` or pydantic schema
  validation for Python; for `$where` specifically, the
  guidance is "refactor to a structured filter expression
  — do not use `$where` on user input at all."

  Discriminator tests ensure these patterns are NOT
  flagged:
  - `String(req.body.user)` / `Number(req.body.id)` coerced
    values (the documented safe pattern).
  - `str(request.json['user'])` coercion in Python.
  - Literal filter values (`{ user: 'alice' }`).
  - Intermediate-variable flows (out of scope; documented
    as the taint-analysis boundary).

  `RSTR-NOSQLI-001` and `-003` deliberately skip filter
  objects that contain a `$` operator (e.g. `{ $where: ... }`),
  so the `$where` rule (`-002`) fires on its own without a
  duplicate `-001` finding on the same line.

## [0.3.0] - 2026-06-14

### Added

- **`--format html`** output format. Writes a single self-
  contained HTML report to the path given by `-o/--output`
  (an HTML report cannot stream to stdout, so `-o` is
  required). The report includes a header with the finding
  count and scan time, an SVG severity donut, a category
  bar chart, a search-box + per-severity filter chips, and a
  sortable findings table with click-to-sort column headers.
  CSS and JS are vendored inside the binary and inlined at
  render time — no external scripts, no CDN, no network at
  view time, no localhost daemon. Open with any browser
  (`start report.html` on Windows, `open` on macOS,
  `xdg-open` on Linux) or drag-and-drop into a browser
  window. Respects `prefers-color-scheme` for light/dark.
  At <720 px the table collapses into stacked cards so it
  stays readable on phones.

- **`--format markdown`** output format. Renders a self-
  contained PR-comment-ready summary: a one-line header
  (finding count + files scanned + total time), a Severity
  table, a Category table, and per-severity finding tables
  collapsed in `<details>` blocks. Default cut-offs: all
  Critical findings, up to 10 High, 5 Medium, 5 Low; Info is
  omitted from the finding tables (counted in the Severity
  table). The remainder per bucket is summarized with a
  pointer to `--format json` for the full list. Drop straight
  into `gh pr comment --body-file scan.md` or post via a
  GitHub Actions step.

- **Crawler now skips minified files by default.** Files
  whose name contains `.min.js`, `.min.css`, `.min.mjs`,
  `.min.cjs`, `.bundle.js`, `.bundle.mjs`, `.bundle.css`,
  `-min.js`, or `-min.css` are skipped, as are non-minified-
  named JS/TS/CSS files whose first 8 KB has an average line
  length over 500 characters. This catches vendored
  jQuery/Bootstrap and bundler output that produced
  unactionable findings (RSTR-CRY-005, RSTR-PERF-101) with
  source-context blocks rendering as opaque minified strings.
  Pass `--include-minified` to scan them anyway.

## [0.2.1] - 2026-06-14

### Added

- **`[[suppress]]` table in `.rastray.toml`** for path + rule
  allow-listing. Each entry takes a `path` glob, an optional
  `rules` array (defaults to `["*"]` to suppress all codes at
  that path), and an optional `reason` string. Glob patterns
  follow gitignore syntax — `src/modules/secrets.rs`,
  `vendor/**`, `tests/fixtures/*.js` all work. Useful when an
  analyzer matches its own pattern definitions, when test
  fixtures intentionally contain example tokens, or when a
  vendored directory has known-acceptable findings. Example:

  ```toml
  [[suppress]]
  path = "src/modules/secrets.rs"
  rules = ["RSTR-SEC-001", "RSTR-SEC-002"]
  reason = "rule definitions and test fixtures"
  ```

### Fixed

- **`RSTR-PTH-004` no longer fires on ES-module / CommonJS / Rust
  `use` imports.** The literal-`../../` heuristic now inspects the
  line containing the match and skips it if the line is an
  `import ... from '...'`, `export ... from '...'`,
  `from ... import ...`, `require('...')`, `import('...')`, or
  Rust `use crate::...;` statement. On a real JS/TS monorepo this
  removes hundreds of false positives that were just relative
  import specifiers, not file-system access. The rule severity is
  also lowered from `low` to `info` to reflect that it is a
  heuristic substring match, not taint analysis; pass
  `--min-severity info` to see it.

- **`RSTR-PERF-102` (and `RSTR-PERF-101`) no longer fire when the
  expression is in the init / condition / update of a `for`
  statement.** The "inside a loop" check now walks the parent
  chain and only counts a `for`/`for-in`/`for-of` ancestor when
  the path entered through its `body` field. Expressions that
  run **once** at loop entry (`for (let d = new Date(start); ...)`,
  `for (const u of await getUrls())`, `for (const k of new Map())`)
  no longer trip these rules. `while` / `do-while` conditions
  still count (they re-evaluate every iteration). A representative
  NestJS + Next monorepo drops from 15 to 10 PERF-102 findings,
  all 10 remaining being legitimate in-body allocations.

- **`RSTR-PERF-001` is now scoped to the string-accumulation
  pattern it was originally meant to catch.** Previously it fired
  on any `format!` call inside any loop body, which matched all
  routine error-message construction, struct-field initialisers,
  `Finding::new(...)` arguments, and one-time cache-key building
  — none of which are hot-path bugs. The rule now requires the
  `format!` result to flow into a string accumulator: either as
  the argument of a `.push_str(...)` call, or as the right-hand
  side of a `+=` compound assignment. The message and severity
  are unchanged for true positives. A self-scan on this repo
  drops 8 false positives.

- **`.rastray.toml` `[scan.ignore].paths` (and the new
  `[[suppress]]` block) now match findings whose locations carry
  canonical absolute paths.** Previously the gitignore matcher
  was tested against the raw finding path while the matcher was
  rooted at the canonicalized scan root, so on Windows
  (`\\?\C:\…`) and any setup where the scan target was
  canonicalized at crawl time, `paths = ["target/**"]` would
  silently fail to match anything. The applier now relativises
  every finding's path to the canonical scan root before
  asking the matcher.

- **Inline summary block's Category distribution now shows the
  correct count next to each label, includes a `Security` row,
  and no longer panics on `Category::Internal` findings.** The
  previous implementation used a 5-slot count array against
  6 enum variants, with the label list missing `Security`, so on
  any scan with security or dependency findings the counts were
  shifted by one (e.g. security counts rendered under the
  `Dependencies` label) and an `Internal`-category finding would
  index out of bounds and panic. Each category now has an
  explicit label-to-variant pair, and `category_counts` is now a
  testable helper with three regression tests guarding the
  pairing, the no-panic path for `Internal`, and exhaustive
  variant coverage.

- Release workflow now populates the GitHub Release body from the
  annotated tag's message (`body_path: release_notes.md` extracted
  via `git tag -l --format='%(contents:body)'`). Previously the
  release was created with an empty body even though the tag
  carried full release notes.

### Changed

- README now displays Crates.io version and download badges.

## [0.2.0] - 2026-06-14

### Changed

- **Example GitHub Actions workflow** (`examples/github-actions/`)
  now demonstrates the full Phase 8 surface: PR runs use
  `--since origin/<base_ref>` for ~24x faster incremental scans, a
  new `sbom` job uploads CycloneDX and SPDX artifacts on every push
  to `main`, and the README shows the baseline-adoption workflow.

### Added

- **Path-traversal analyzer** (`RSTR-PTH-*`) for file-system
  sinks that consume web-request input: Flask `send_file`
  (RSTR-PTH-001), Express `res.sendFile` /
  `fs.readFile`/`writeFile`/`createReadStream` (RSTR-PTH-002),
  Java `new File(request.getParameter(...))` (RSTR-PTH-003),
  and literal `../../` substrings in source (RSTR-PTH-004).
  Note: this is heuristic regex matching, not taint analysis;
  some false positives expected for intentional, sanitized
  paths.
- **Insecure-deserialization analyzer** (`RSTR-DES-*`) for known
  RCE-via-deserialization sinks: Python `pickle.loads` / `pickle.load`
  / `pickle.Unpickler` (RSTR-DES-001), Python `yaml.load` without
  SafeLoader (RSTR-DES-002), Python `marshal.loads` (RSTR-DES-003),
  Node `node-serialize.unserialize` (RSTR-DES-004), Ruby
  `Marshal.load` (RSTR-DES-005), Java `ObjectInputStream` /
  `.readObject()` (RSTR-DES-006), and PHP `unserialize()`
  (RSTR-DES-007). All five Critical except for `yaml.load`
  which is High (depends on resolved Loader).
- **Dockerfile / IaC analyzer** (`RSTR-IAC-*`) targeting
  `Dockerfile`, `Containerfile`, and variants (`Dockerfile.<x>`,
  `<x>.dockerfile`): image pinned to `:latest` or no tag at all
  (RSTR-IAC-001), explicit `USER root` (RSTR-IAC-002), `ADD` with
  a remote URL (RSTR-IAC-003), `chmod 777` (RSTR-IAC-005),
  and `curl ... | sh` pipe-to-shell installers (RSTR-IAC-006).
- **GitHub Actions workflow lint** (`RSTR-GHA-*`) targeting
  `.github/workflows/*.{yml,yaml}` files:
  `pull_request_target` (RSTR-GHA-001), third-party actions
  pinned by floating tag instead of a SHA (RSTR-GHA-002),
  `${{ github.event.*.body }}` (and similar) interpolated into
  `run:` scripts (RSTR-GHA-003), and `persist-credentials: true`
  on `actions/checkout` (RSTR-GHA-005). Note: only files under
  `.github/workflows/` are inspected.
- **TLS/network analyzer** (`RSTR-NET-*`) for transport-layer
  misconfigurations: TLS verification disabled
  (`verify=False`, `rejectUnauthorized: false`,
  `InsecureSkipVerify: true`) (RSTR-NET-001), SSL hostname
  checking disabled or `CERT_NONE` (RSTR-NET-002), CORS wildcard
  with `credentials: true` and `Access-Control-Allow-Origin: *`
  (RSTR-NET-003), explicit `httpOnly: false` on cookies
  (RSTR-NET-004). Language coverage: Python, JS/TS, Go.
- **Injection analyzer** (`RSTR-INJ-*`) for code-injection
  patterns: SQL built with f-strings or template literals
  (RSTR-INJ-001), `subprocess` with `shell=True` or `os.system`
  with a string arg (RSTR-INJ-002), `eval`/`exec`/`new Function`
  on user-influenced input (RSTR-INJ-003), `child_process.exec`
  with a template literal or string concatenation
  (RSTR-INJ-004), and Go `exec.Command("sh", "-c", ...)`
  (RSTR-INJ-005). Language coverage: Python, JS/TS, Go, PHP.
- **Insecure-crypto analyzer** (`RSTR-CRY-*`) for high-severity
  weak-crypto patterns: MD5/SHA-1 used for hashing, DES/3DES
  ciphers, ECB mode, `Math.random()` for tokens (JS/TS), Python
  `random` module for tokens, Go `math/rand` for tokens, Rust
  `thread_rng()` for tokens. Language coverage: Python, JS/TS,
  Java/Kotlin, Go, and Rust. Findings are reported under the new
  `security` category.
- **Java/Kotlin lockfile support** for Maven (`pom.xml` direct
  dependencies) and Gradle (`gradle.lockfile`). Maven's `pom.xml`
  parser walks `<dependencies>` blocks while skipping the
  `<dependencyManagement>` section, and skips entries whose
  `<version>` is a `${property}` reference (those require
  property resolution we don't do). Gradle's `gradle.lockfile`
  parser handles the `group:name:version=<configs>` line format
  and skips `empty=` and `#` comment lines. Both feed OSV `Maven`
  and emit `pkg:maven/<groupId>/<artifactId>@<version>` purls
  (the first `:` is rewritten to `/` for purl spec compliance).
- **Elixir lockfile support** for `mix.lock` (Hex). Walks the
  Erlang-term-formatted lockfile line-by-line, extracts the two
  quoted strings from each `{:hex, :atom, "version", ...}` tuple
  (the package name and version), and skips entries from non-hex
  sources like `{:git, ...}`. Feeds OSV `Hex` and emits
  `pkg:hex/<name>@<version>` purls.
- **Dart/Flutter lockfile support** for `pubspec.lock`. Hand-rolled
  YAML walker (matching the style of the existing `pnpm-lock.yaml`
  parser) extracts the package name and version under the
  top-level `packages:` block. Feeds OSV `Pub` and emits
  `pkg:pub/<name>@<version>` purls.
- **Swift lockfile support** for `Package.resolved` (SwiftPM).
  Handles both the v1 schema (`object.pins`) and the current v2
  schema (top-level `pins`). Package names are normalized to
  `<host>/<owner>/<repo>` (lowercased, `https://` and `.git`
  stripped, `git@host:` rewritten to `host/`) so purls follow the
  `pkg:swift/github.com/apple/swift-syntax@<version>` shape
  expected by the purl spec. Pins without a resolved version
  (branch-only refs) are skipped. Feeds OSV `SwiftURL`.
- **.NET lockfile support** for `packages.lock.json` (NuGet).
  Walks every target framework moniker (TFM) under the
  `dependencies` root and deduplicates packages shared across
  TFMs by `(name, resolved_version)`. Includes both `Direct` and
  `Transitive` dependency types. Feeds OSV `NuGet` and emits
  `pkg:nuget/<name>@<version>` purls. Note: NuGet lockfiles are
  only generated when `RestorePackagesWithLockFile` is enabled in
  the project file.
- **PHP lockfile support** for `composer.lock` (Composer). Adds
  CVE scanning against the OSV `Packagist` ecosystem and emits
  `pkg:composer/<vendor>/<name>@<version>` purls. Both the
  `packages` and `packages-dev` sections are walked. Leading `v`
  prefixes on Composer versions are stripped to match OSV's
  canonical form.
- **Ruby lockfile support** for `Gemfile.lock` (Bundler). Adds
  CVE scanning against the OSV `RubyGems` ecosystem and emits
  `pkg:gem/...` purls in CycloneDX and SPDX SBOMs. Only top-level
  resolved specs are reported; nested dependency constraints under
  each spec are intentionally skipped to avoid duplicate entries.
- **Python lockfile support** for `poetry.lock`, `Pipfile.lock`, and
  `uv.lock`. These join the existing `requirements.txt` parser, so
  Poetry, Pipenv, and uv projects now get full CVE scanning *and*
  SBOM coverage out of the box. All three feed the same `PyPI` OSV
  ecosystem and emit `pkg:pypi/...` purls.
- **SBOM output** in two industry-standard formats.
  `--format cyclonedx` emits CycloneDX 1.5 JSON; `--format spdx-json`
  emits SPDX 2.3 JSON. Both reuse the lockfile parsers rastray
  already uses for CVE detection (cargo, npm, pnpm, yarn, pip, go),
  so a single binary now covers vulnerability scanning *and* SBOM
  generation. Each package is exported with a purl identifier for
  drop-in compatibility with Dependency-Track, Grype, GitHub's
  dependency graph, etc. SBOM formats skip analyzers and run in
  roughly walk-time.
- **Incremental scanning** for fast PR CI. `--since <REF>` (e.g.
  `--since origin/main`) restricts analyzers to files changed against
  the given git ref. `--changed-only` is shorthand for `--since HEAD~1`.
  On a real 1,007-file repo, scanning a single-file PR drops from
  ~12 s (full scan) to under 1 s.
- **Baseline mode** for incremental adoption on existing codebases.
  `--write-baseline <FILE>` snapshots the current findings to a JSON
  file (deduplicated, fingerprinted by `(code, file, line, message)`).
  `--baseline <FILE>` loads that file and drops every finding whose
  fingerprint matches an entry before `--fail-on` is evaluated, so
  only **new** findings can fail the build. Verified end-to-end
  against a real project with 161 baseline findings: the second scan
  reports zero findings.

## [0.1.4] - 2026-06-14

### Fixed

- `cosign sign-blob` is now invoked twice per release archive so that
  `.sig` and `.crt` sidecars actually land in the GitHub Release
  alongside `.cosign.bundle`. cosign 2.x silently drops
  `--output-signature` and `--output-certificate` when `--bundle` is
  passed in the same call, so v0.1.3 shipped without the legacy
  sidecars that the OSSF Scorecard `Signed-Releases` check looks for.

## [0.1.3] - 2026-06-14

### Added

- Release archives now ship with **SLSA build-provenance attestations**
  produced by `actions/attest-build-provenance`. Verify with
  `gh attestation verify <archive> --repo balangyaoejuspher/rastray`.
  Satisfies the OSSF Scorecard `Provenance` check.
- Each archive's cosign keyless signature is now also emitted as
  standalone `.sig` + `.crt` sidecars alongside the existing
  `.cosign.bundle`. The `.sig` form is the file extension recognized by
  the OSSF Scorecard `Signed-Releases` check.

## [0.1.2] - 2026-06-14

### Added

- The dependency analyzer now parses **`pnpm-lock.yaml`** (both v6
  slash-prefix and v9 no-prefix entry styles) and **`yarn.lock`** (v1
  classic format and v2/v3 Berry YAML format). All extracted packages
  feed the existing OSV.dev vulnerability lookup pipeline as the `npm`
  ecosystem.

### Fixed

- OSV batch queries now chunk into groups of 1000 packages each,
  matching OSV.dev's documented per-request limit. Previously, scanning
  a project with more than 1000 lockfile entries failed with
  `400 Bad Request` and the dependency analyzer reported no findings.

## [0.1.1] - 2026-06-14

Maintenance release: CI hygiene and supply-chain hardening. No
functional code changes.

### Added

- Release archives are now signed with [Sigstore](https://www.sigstore.dev/)
  cosign keyless OIDC. Each `.tar.gz` and `.zip` ships with a matching
  `.cosign.bundle` sidecar that proves the artifact was built by this
  repository's tagged release workflow. Verification command and
  certificate identity documented in [`install/README.md`](install/README.md).

### Changed

- `release.yml` now follows least privilege: top-level `GITHUB_TOKEN`
  permissions are `contents: read`, with only the `binaries` and
  `installers` jobs explicitly escalating to `contents: write` to
  upload release assets. Lifts OSSF Scorecard `Token-Permissions`
  to a passing score.
- All workflows bumped to Node.js 24-compatible action runtimes ahead
  of the GitHub Actions Node 20 deprecation deadline:
  - `actions/checkout` v4.2.2 → v6.0.3
  - `actions/cache` v4 → v5.0.5
  - `softprops/action-gh-release` v2 → v3.0.0

## [0.1.0] - 2026-06-13

First public release. `rastray` is a polyglot static analysis CLI that
ships secret detection, dependency vulnerability scanning, and per-language
performance analyzers in a single binary.

### Added

#### Analyzers

- **Secret detection** — eight regex patterns out of the box: AWS access
  key (`AKIA*`), GitHub PAT (classic `ghp_*` and fine-grained
  `github_pat_*`), Slack bot (`xoxb-*`), Stripe live (`sk_live_*`),
  Google API (`AIza*`), PEM private key, npm token (`npm_*`). Shannon
  entropy filtering (default threshold 3.0) suppresses placeholders and
  example tokens; PEM headers bypass the entropy gate.
- **Dependency vulnerabilities** — parses `Cargo.lock`,
  `package-lock.json`, `requirements.txt`, and `go.sum`, then queries
  [OSV.dev](https://osv.dev) `/v1/querybatch` with per-vulnerability
  hydration. CVSS v3/v4 and GHSA textual severity mapping. Findings are
  cached for 24 h in `%LOCALAPPDATA%\rastray\osv-cache.json` (Windows) or
  `$XDG_CACHE_HOME/rastray/` (Linux); override with `$RASTRAY_CACHE_DIR`.
- **Performance** (tree-sitter ASTs) across Rust, TypeScript / JavaScript
  / TSX, Python, and Go:
  - Rust — `format!` in loops, `.clone()` on iterators inside `for`
  - TypeScript / JavaScript — `await` in loops, `new Date()` in loops
  - Python — string `+=` in loops, `time.sleep` in `async def`
  - Go — `defer` inside `for`, `fmt.Sprintf` in loops

#### Output formats

- `--format human` (default) — `miette`-rendered diagnostics with source
  spans and help text.
- `--format json` — stable schema documented in the README.
- `--format gh-actions` — GitHub Actions workflow commands so findings
  render as inline PR annotations (`error` / `warning` / `notice`).
- `--format sarif` — SARIF 2.1.0 for GitHub Code Scanning and IDE
  integrations. Severities map as Critical/High → `error`,
  Medium → `warning`, Low/Info → `note`.
- `-o, --output <FILE>` routes `json` and `sarif` payloads to disk.

#### Configuration

- `.rastray.toml` is auto-discovered up the directory tree. Override
  with `--config <FILE>` or skip with `--no-config`.
- Per-rule enable/disable and per-rule severity overrides.
- Glob-based ignore paths under `[scan.ignore]`.
- `[scan].fail_on` and matching `--fail-on <LEVEL>` flag control the
  exit code threshold independently of `--min-severity`. Accepts
  `info`, `low`, `medium`, `high`, `critical`, or `never`. Resolution
  order: CLI > config > `--min-severity` default.

#### Suppression

- Inline directives in scanned source files, language-agnostic
  (works inside `//`, `#`, or `/* */` comments):
  - `rastray-ignore: <CODE>` — suppresses the next line
  - `rastray-ignore-line: <CODE>` — suppresses the same line
  - `rastray-ignore-file: <CODE>` — suppresses the whole file
- Comma-separated code lists and the `*` wildcard are supported.

#### Distribution

- Published to <https://crates.io/crates/rastray> —
  `cargo install rastray --locked`.
- Prebuilt binaries for `x86_64-unknown-linux-gnu`,
  `x86_64-apple-darwin`, `aarch64-apple-darwin`, and
  `x86_64-pc-windows-msvc` attached to every release with SHA-256
  sidecars.
- Shell installers (`install.sh`, `install.ps1`) that download,
  verify, and extract the right archive for the host platform.

#### Examples

- [`examples/github-actions/`](examples/github-actions/) — drop-in
  workflow with inline annotations, SARIF upload, and an explicit
  severity gate.
- [`examples/config/`](examples/config/) — four sample
  `.rastray.toml` files (`minimal`, `advisory`, `strict`,
  `monorepo`).

### Security

- No `unsafe`, `unwrap`, `expect`, or `panic!` in production paths.
- TLS via `rustls` only; no OpenSSL surface area.
- Minimal default features on `tokio` and `reqwest`.
- Hardened release profile: `lto = "thin"`, `codegen-units = 1`,
  `strip = "symbols"`, `panic = "abort"`.
- Resolved RustSec advisory `RUSTSEC-2025-0023` (tokio broadcast
  soundness) by pinning `tokio >= 1.47`.

### Compatibility

- MSRV: Rust **1.86.0**.
- The JSON output is considered stable within a minor version. Schema
  additions will be called out in this changelog.

[Unreleased]: https://github.com/balangyaoejuspher/rastray/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/balangyaoejuspher/rastray/releases/tag/v0.3.0
[0.2.1]: https://github.com/balangyaoejuspher/rastray/releases/tag/v0.2.1
[0.2.0]: https://github.com/balangyaoejuspher/rastray/releases/tag/v0.2.0
[0.1.4]: https://github.com/balangyaoejuspher/rastray/releases/tag/v0.1.4
[0.1.3]: https://github.com/balangyaoejuspher/rastray/releases/tag/v0.1.3
[0.1.2]: https://github.com/balangyaoejuspher/rastray/releases/tag/v0.1.2
[0.1.1]: https://github.com/balangyaoejuspher/rastray/releases/tag/v0.1.1
[0.1.0]: https://github.com/balangyaoejuspher/rastray/releases/tag/v0.1.0
