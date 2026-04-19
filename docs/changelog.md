# Changelog

## Storage

Two locations:

- **`changelog.d/*.toml`** — one TOML file per unreleased entry. Each PR with a user-visible change adds its own file, so concurrent PRs don't touch the same bytes and don't conflict on the changelog. `release.py` rotates these files into the JSON and deletes them.
- **`lsposed/app/src/main/assets/changelog.json`** — bilingual (en/ru), released history only:

  ```json
  { "history": [
      { "version": "0.6.1", "sections": [...] },
      { "version": "0.6.0", "sections": [...] }
  ] }
  ```

  `history[0]` is the most recent released version. No `unreleased` field — those live in `changelog.d/` until a release promotes them.

### Fragment file format

```toml
type = "fixed"
en = """
App no longer crashes when …
"""
ru = """
Приложение больше не падает когда …
"""
```

Types: `added`, `changed`, `fixed`, `removed`, `deprecated`, `security`. Triple-quoted multiline strings are stripped of leading/trailing whitespace when loaded.

## Generated files (do NOT edit by hand)

Two markdown files are regenerated from `changelog.d/` + JSON by `scripts/changelog_lib.py`:

- `CHANGELOG.md` at repo root — full history, Keep a Changelog format. Renders `## [Unreleased]` on top when `changelog.d/` has fragments, then each history entry as `## vX.Y.Z`. CI extracts a single `## vX.Y.Z` block for the **GitHub release body**, so don't edit release notes by hand either.
- `update-json/changelog.md` — last 5 **released** versions only (no Unreleased block). Shown by Magisk/KSU in the update popup inside the manager app.

## Adding an entry

From a PR branch:

```sh
./scripts/changelog.py <type> "<EN text>" "<RU text>"
```

Writes `changelog.d/<timestamp>-<slug>.toml` and regenerates both markdown files. Commit the new fragment file + `CHANGELOG.md` alongside your code change (the update-json markdown only changes on release).

Pass `--slug <slug>` if the auto-derived slug collides with an existing fragment — filenames already carry a second-precision timestamp, so collisions are rare.

## When to add an entry

Add one for user-visible changes:

- new features / behaviour changes
- bug fixes that affect released versions
- security fixes
- breaking changes (also bump major/minor as appropriate)

Skip for: internal refactors with no behaviour change, documentation-only changes, CI/build tweaks, test additions.

## Cutting a release

See [releasing.md](releasing.md). The release script rotates every fragment under `changelog.d/` into `history[0]` atomically with the version bump and deletes the fragment files — no separate "rotate" step.
