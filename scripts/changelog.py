#!/usr/bin/env -S uv run --script
#
# /// script
# requires-python = ">=3.12"
# dependencies = [
#   "rich",
# ]
# ///
"""Create a bilingual unreleased changelog fragment.

Usage:
  changelog.py <type> "<EN text>" "<RU text>" [--slug SLUG]

Types: added, changed, fixed, removed, deprecated, security

Writes a TOML file to `changelog.d/<timestamp>-<slug>.toml`. Each
fragment is a single entry; `release.py` rotates them all into history
and deletes them. Because each PR adds its own file, concurrent PRs
don't conflict on the changelog.

The slug defaults to the first few words of the English text; pass
`--slug` to override (e.g. if the auto-slug collides with a teammate's
fragment — rare because filenames carry a second-precision timestamp).

Regenerates `CHANGELOG.md` (Unreleased block at the top, sourced from
fragments) and `update-json/changelog.md` (release history only).
"""

from __future__ import annotations

import argparse
import re
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from changelog_lib import (  # type: ignore[import-not-found]
    FRAGMENTS_DIR,
    VALID_TYPES,
    load_fragments,
    load_json,
    write_md,
)
from rich.console import Console

MAX_SLUG_WORDS = 6
MAX_SLUG_LEN = 50
_SLUG_SCRUB = re.compile(r"[^a-z0-9]+")


def auto_slug(text: str) -> str:
    """Lowercase, keep alphanumerics, collapse runs of anything else to a
    single dash, take the first few words. Non-Latin (Cyrillic) chars
    get stripped — we slugify the EN text where that's not an issue.
    """
    lower = text.lower()
    scrubbed = _SLUG_SCRUB.sub("-", lower).strip("-")
    words = scrubbed.split("-")[:MAX_SLUG_WORDS]
    slug = "-".join(w for w in words if w)[:MAX_SLUG_LEN]
    return slug or "entry"


def fragment_path(slug: str) -> Path:
    """Disambiguate on the rare collision by appending -2, -3, ..."""
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    FRAGMENTS_DIR.mkdir(parents=True, exist_ok=True)
    base = FRAGMENTS_DIR / f"{timestamp}-{slug}.toml"
    if not base.exists():
        return base
    n = 2
    while True:
        candidate = FRAGMENTS_DIR / f"{timestamp}-{slug}-{n}.toml"
        if not candidate.exists():
            return candidate
        n += 1


def write_fragment(path: Path, type_: str, en: str, ru: str) -> None:
    # Hand-rolled TOML writer (stdlib only). Triple-quoted multiline
    # strings keep long entries readable in diffs and avoid quote
    # escaping.
    body = (
        f'type = "{type_}"\n'
        f'en = """\n{en}\n"""\n'
        f'ru = """\n{ru}\n"""\n'
    )
    path.write_text(body, encoding="utf-8")


def main() -> int:
    console = Console()
    parser = argparse.ArgumentParser(description="Create an unreleased changelog fragment.")
    parser.add_argument("type", choices=VALID_TYPES)
    parser.add_argument("en", help="English text")
    parser.add_argument("ru", help="Russian text")
    parser.add_argument("--slug", help="custom slug (default: derived from EN text)")
    args = parser.parse_args()

    slug = args.slug or auto_slug(args.en)
    path = fragment_path(slug)
    write_fragment(path, args.type, args.en.strip(), args.ru.strip())

    data = load_json()
    fragments = load_fragments()
    write_md(data, fragments)

    console.print(f"[green]wrote[/green] {path.relative_to(Path.cwd())}")
    console.print(f"  [cyan]type:[/cyan] {args.type}")
    console.print(f"  [cyan]en:[/cyan]   {args.en}")
    console.print(f"  [cyan]ru:[/cyan]   {args.ru}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
