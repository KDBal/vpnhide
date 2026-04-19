# Unreleased changelog fragments

Each file here is a single entry that will land in the next release.
`./scripts/release.py` rotates them all into `history[0]` of
`lsposed/app/src/main/assets/changelog.json` and deletes the files.

## Adding an entry

```sh
./scripts/changelog.py <type> "<EN text>" "<RU text>"
```

Types: `added`, `changed`, `fixed`, `removed`, `deprecated`, `security`.

This writes `changelog.d/YYYYMMDDHHMMSS-<slug>.toml` and regenerates
`CHANGELOG.md` + `update-json/changelog.md`.

Commit the new fragment alongside your code change.

## Why a directory of fragments instead of a single file

Every PR that edits the same JSON/MD section conflicts with every other
PR doing the same. Fragments sidestep that: each PR adds its own file,
so merges don't touch the same bytes.

The timestamp-prefixed filenames keep rendered order roughly
chronological without relying on git diff order. `.gitattributes` marks
`*.toml` here as `merge=union` as a belt-and-suspenders fallback if two
PRs somehow pick the exact same filename (rare — filenames include a
second-precision timestamp plus a slug).

## Fragment file format (TOML)

```toml
type = "fixed"
en = """
App no longer crashes when …
"""
ru = """
Приложение больше не падает когда …
"""
```

Leading/trailing whitespace inside the triple-quoted strings is stripped
when the fragment is loaded. Do not commit fragments by hand unless
you know what you're doing — prefer the `changelog.py` script.
