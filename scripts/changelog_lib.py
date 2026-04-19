"""Shared helpers for changelog manipulation.

Used by `changelog.py` (create unreleased fragment), `release.py`
(rotate fragments into history + bump version files) and the
markdown-generation pipeline.

Storage layout:

* `lsposed/app/src/main/assets/changelog.json` — bilingual release
  history. Source of truth for everything that's already shipped.

      { "history": [ { "version": "0.6.1", "sections": [...] }, ... ] }

* `changelog.d/*.toml` — one TOML file per pending entry. Each file is
  a single unreleased item:

      type = "fixed"
      en   = "..."
      ru   = "..."

  Fragments live on disk and are accumulated across PRs. Because each
  entry is its own file, two PRs concurrently adding entries don't
  touch the same bytes and don't conflict. `release.py` rotates all
  fragments into `history[0]` and deletes them.

Generated (overwritten every script run, never hand-edited):

* `CHANGELOG.md` at the repo root — Keep a Changelog, full history with
  an optional `## [Unreleased]` block sourced from the fragments.
* `update-json/changelog.md` — last MD_RECENT_VERSIONS released
  versions, no Unreleased. Served to Magisk/KSU update popups.
"""

from __future__ import annotations

import json
import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
JSON_PATH = REPO_ROOT / "lsposed/app/src/main/assets/changelog.json"
FULL_MD_PATH = REPO_ROOT / "CHANGELOG.md"
SHORT_MD_PATH = REPO_ROOT / "update-json/changelog.md"
FRAGMENTS_DIR = REPO_ROOT / "changelog.d"

VALID_TYPES = ("added", "changed", "fixed", "removed", "deprecated", "security")
MD_RECENT_VERSIONS = 5

_KEEP_A_CHANGELOG_HEADER = """# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

"""


def load_json() -> dict:
    return json.loads(JSON_PATH.read_text(encoding="utf-8"))


def save_json(data: dict) -> None:
    JSON_PATH.write_text(
        json.dumps(data, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def load_fragments() -> list[dict]:
    """Read every `*.toml` under `changelog.d/`, sorted by filename so
    the rendered order is deterministic (filenames carry a timestamp
    prefix, so order ≈ chronological).
    """
    if not FRAGMENTS_DIR.is_dir():
        return []
    fragments: list[dict] = []
    for path in sorted(FRAGMENTS_DIR.glob("*.toml")):
        data = tomllib.loads(path.read_text(encoding="utf-8"))
        type_ = data.get("type")
        en_raw = data.get("en")
        ru_raw = data.get("ru")
        if type_ not in VALID_TYPES:
            raise ValueError(f"{path}: type must be one of {VALID_TYPES}, got {type_!r}")
        if not isinstance(en_raw, str) or not en_raw.strip():
            raise ValueError(f"{path}: missing or empty 'en'")
        if not isinstance(ru_raw, str) or not ru_raw.strip():
            raise ValueError(f"{path}: missing or empty 'ru'")
        # Triple-quoted TOML strings keep the trailing \n before the
        # closing """; strip so rendered markdown doesn't grow blank lines.
        fragments.append({"path": path, "type": type_, "en": en_raw.strip(), "ru": ru_raw.strip()})
    return fragments


def fragments_as_sections(fragments: list[dict]) -> list[dict]:
    """Group flat fragment list into the same shape used by history
    entries: `[{"type": T, "items": [{"en", "ru"}, ...]}, ...]`.
    Empty types are skipped. Order follows VALID_TYPES.
    """
    by_type: dict[str, list[dict]] = {}
    for fragment in fragments:
        by_type.setdefault(fragment["type"], []).append(
            {"en": fragment["en"], "ru": fragment["ru"]},
        )
    sections: list[dict] = []
    for type_ in VALID_TYPES:
        items = by_type.get(type_)
        if items:
            sections.append({"type": type_, "items": items})
    return sections


def _section_items(entry: dict) -> list[tuple[str, list[dict]]]:
    """Return [(type, items), ...] for an entry in canonical order,
    skipping types with no items.
    """
    sections_by_type = {s["type"]: s for s in entry.get("sections", [])}
    out: list[tuple[str, list[dict]]] = []
    for type_ in VALID_TYPES:
        section = sections_by_type.get(type_)
        if section and section.get("items"):
            out.append((type_, section["items"]))
    return out


def _render_entry(heading: str, entry: dict, out: list[str]) -> None:
    out.append(f"## {heading}")
    out.append("")
    for type_, items in _section_items(entry):
        out.append(f"### {type_.title()}")
        for item in items:
            out.append(f"- {item['en']}")
        out.append("")


def render_full_md(data: dict, fragments: list[dict]) -> str:
    """Full history (with optional Unreleased block on top from
    fragments), Keep a Changelog header.
    """
    out: list[str] = []
    unreleased_sections = fragments_as_sections(fragments)
    if unreleased_sections:
        _render_entry("[Unreleased]", {"sections": unreleased_sections}, out)
    for entry in data.get("history", []):
        _render_entry(f"v{entry['version']}", entry, out)
    return _KEEP_A_CHANGELOG_HEADER + "\n".join(out).rstrip() + "\n"


def render_short_md(data: dict) -> str:
    """Last MD_RECENT_VERSIONS released versions only, no Unreleased,
    no preamble. For Magisk/KSU popup.
    """
    out: list[str] = []
    for entry in data.get("history", [])[:MD_RECENT_VERSIONS]:
        _render_entry(f"v{entry['version']}", entry, out)
    return "\n".join(out).rstrip() + "\n"


def write_md(data: dict, fragments: list[dict]) -> None:
    FULL_MD_PATH.write_text(render_full_md(data, fragments), encoding="utf-8")
    SHORT_MD_PATH.write_text(render_short_md(data), encoding="utf-8")


def rotate_fragments_into_history(
    data: dict,
    fragments: list[dict],
    version: str,
) -> dict:
    """Promote the current fragment set into `history[0]` with the given
    version, then delete the fragment files. Returns the newly-released
    entry.
    """
    released = {
        "version": version,
        "sections": fragments_as_sections(fragments),
    }
    history = data.setdefault("history", [])
    history.insert(0, released)
    for fragment in fragments:
        fragment["path"].unlink()
    return released
