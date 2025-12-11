"""
Utility script to check that consent form files are in sync across:

1) GitHub repo: petrenca/German_Lexicon_Project (consent_forms/)
2) GitHub repo: schiekiera/German_Lexicon_Project (consent_forms/)
3) HU server   : https://amor.cms.hu-berlin.de/~petrenal/GermanLexiconProject/jspsych.8.2.1/consent_forms

The script performs two checks:

1. Filename presence:
   - Retrieve the list of files with extensions
     *.html, *.json, *.py from each of the three locations.
   - Compare filenames across sources.
   - Print all files that are missing from at least one location,
     indicating for each file where it is present/absent.

2. File content equality:
   - For every filename present in all three locations, load the contents
     directly into memory (no local saving).
   - GitHub contents are fetched via raw.githubusercontent.com URLs.
   - Compare the three versions by hash.
   - Print all files whose contents differ and show which sources share
     identical content (if any).

Requires no external dependencies; only Python standard library.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Dict, List, Set
from urllib.error import URLError, HTTPError
from urllib.request import urlopen, Request
import difflib

FILE_EXTENSIONS = (".html", ".json", ".py")

# Directory listing URLs (for reference / documentation)
github_url_petrenca = (
    "https://github.com/petrenca/German_Lexicon_Project/tree/main/consent_forms"
)
github_url_schiekiera = (
    "https://github.com/schiekiera/German_Lexicon_Project/tree/main/consent_forms"
)
hu_server_url = (
    "https://amor.cms.hu-berlin.de/~petrenal/GermanLexiconProject/"
    "jspsych.8.2.1/consent_forms"
)

# GitHub API endpoints for listing contents of consent_forms/ (JSON)
GITHUB_API_PETRENCA = (
    "https://api.github.com/repos/petrenca/German_Lexicon_Project/contents/consent_forms"
)
GITHUB_API_SCHIEKIERA = (
    "https://api.github.com/repos/schiekiera/German_Lexicon_Project/contents/consent_forms"
)

# Raw content base URLs for GitHub
RAW_BASE_PETRENCA = (
    "https://raw.githubusercontent.com/petrenca/German_Lexicon_Project/main/consent_forms"
)
RAW_BASE_SCHIEKIERA = (
    "https://raw.githubusercontent.com/schiekiera/German_Lexicon_Project/main/consent_forms"
)


@dataclass
class SourceListing:
    name: str
    filenames: Set[str]


def _http_get(url: str) -> bytes:
    """Fetch URL and return raw bytes, raising on HTTP errors."""
    req = Request(url, headers={"User-Agent": "consent-sync-checker/1.0"})
    try:
        with urlopen(req) as resp:
            return resp.read()
    except HTTPError as e:
        raise RuntimeError(f"HTTP error {e.code} for {url}") from e
    except URLError as e:
        raise RuntimeError(f"Network error for {url}: {e.reason}") from e


def list_github_html_files(api_url: str, source_name: str) -> SourceListing:
    """
    Use GitHub API to list relevant files in consent_forms/ for a given repo.
    Relevant = files ending with FILE_EXTENSIONS (top-level only, no recursion).
    """
    raw = _http_get(api_url)
    try:
        data = json.loads(raw.decode("utf-8"))
    except json.JSONDecodeError as e:
        raise RuntimeError(f"Failed to decode JSON from {api_url}: {e}") from e

    filenames: Set[str] = set()
    if isinstance(data, list):
        for item in data:
            if not isinstance(item, dict):
                continue
            if item.get("type") != "file":
                continue
            name = item.get("name")
            if not isinstance(name, str):
                continue
            if name.lower().endswith(FILE_EXTENSIONS):
                filenames.add(name)
    else:
        raise RuntimeError(
            f"Unexpected JSON structure from GitHub API at {api_url!r} "
            f"(expected list, got {type(data).__name__})"
        )

    return SourceListing(name=source_name, filenames=filenames)


def list_hu_html_files(listing_url: str) -> SourceListing:
    """
    Retrieve the directory listing from the HU server and extract
    filenames with extensions in FILE_EXTENSIONS.
    Assumes a simple index page with links like href="consent_form_xxx.html".
    """
    html = _http_get(listing_url).decode("utf-8", errors="replace")

    # Very simple href matcher for relevant files (relative links).
    # This deliberately ignores absolute URLs and anchors.
    candidates = re.findall(
        r'href=["\']([^"\']+\.(?:html|json|py))["\']', html, flags=re.IGNORECASE
    )

    # Normalize: take only basename portion (strip possible paths)
    filenames = {c.split("/")[-1] for c in candidates}

    return SourceListing(name="hu_server", filenames=filenames)


def fetch_file_contents(source: str, filename: str) -> bytes:
    """
    Fetch file contents for a given source and filename using the appropriate base URL.
    - source: one of {"petrenca", "schiekiera", "hu_server"}
    """
    if source == "petrenca":
        url = f"{RAW_BASE_PETRENCA}/{filename}"
    elif source == "schiekiera":
        url = f"{RAW_BASE_SCHIEKIERA}/{filename}"
    elif source == "hu_server":
        url = f"{hu_server_url}/{filename}"
    else:
        raise ValueError(f"Unknown source: {source}")

    return _http_get(url)


def compute_hash(content: bytes) -> str:
    """Return a short SHA256 hash (first 12 hex chars) for display."""
    return hashlib.sha256(content).hexdigest()[:12]


def print_text_diff(
    a: bytes,
    b: bytes,
    label_a: str,
    label_b: str,
    max_lines: int = 80,
) -> int:
    """
    Print a human-readable unified diff between two text files.
    Returns the number of diff lines printed (0 = no visible textual diff).
    """
    # Decode as UTF-8, but don't crash if something is weird
    text_a = a.decode("utf-8", errors="replace").splitlines(keepends=False)
    text_b = b.decode("utf-8", errors="replace").splitlines(keepends=False)

    diff_iter = difflib.unified_diff(
        text_a,
        text_b,
        fromfile=label_a,
        tofile=label_b,
        lineterm="",
        n=3,  # 3 context lines around changes
    )

    line_count = 0
    print(f"    --- Diff between {label_a} and {label_b} ---")
    for line in diff_iter:
        print(f"      {line}")
        line_count += 1
        if line_count >= max_lines:
            print("      ... (diff truncated) ...")
            break

    return line_count

def main() -> None:
    print("=== 1) Collecting filename listings ===")

    petrenca_listing = list_github_html_files(GITHUB_API_PETRENCA, "petrenca")
    schiekiera_listing = list_github_html_files(GITHUB_API_SCHIEKIERA, "schiekiera")
    hu_listing = list_hu_html_files(hu_server_url)

    sources: Dict[str, SourceListing] = {
        "petrenca": petrenca_listing,
        "schiekiera": schiekiera_listing,
        "hu_server": hu_listing,
    }

    all_filenames: Set[str] = (
        petrenca_listing.filenames
        | schiekiera_listing.filenames
        | hu_listing.filenames
    )

    print(f"  petrenca  : {len(petrenca_listing.filenames)} files")
    print(f"  schiekiera: {len(schiekiera_listing.filenames)} files")
    print(f"  hu_server : {len(hu_listing.filenames)} files")
    print(f"  union     : {len(all_filenames)} distinct filenames\n")

    # --- 1) Filename presence differences ---
    print("=== 2) Filenames missing from at least one location ===")
    any_missing = False
    for fname in sorted(all_filenames):
        present = {
            src_name: (fname in src_listing.filenames)
            for src_name, src_listing in sources.items()
        }
        if not all(present.values()):
            any_missing = True
            status = ", ".join(
                f"{src}: {'YES' if is_present else 'NO '}"
                for src, is_present in present.items()
            )
            print(f"  {fname}: {status}")

    if not any_missing:
        print("  All filenames are present in all three locations.")

    # --- 2) Content equality ---
    print("\n=== 3) Content comparison for files present everywhere ===")

    common_filenames = (
        petrenca_listing.filenames
        & schiekiera_listing.filenames
        & hu_listing.filenames
    )
    print(f"  Files present in all three locations: {len(common_filenames)}\n")

    any_diff = False
    text_diff_files = 0
    text_identical_files = 0

    for fname in sorted(common_filenames):
        contents: Dict[str, bytes] = {}
        hashes: Dict[str, str] = {}

        for src in sources.keys():
            try:
                data = fetch_file_contents(src, fname)
            except RuntimeError as e:
                print(f"  [ERROR] Could not fetch {fname!r} from {src}: {e}")
                data = b""
            contents[src] = data
            hashes[src] = compute_hash(data) if data else "ERROR"

        # If all hashes match (and are not ERROR), we consider the file identical.
        unique_hashes = {h for h in hashes.values() if h != "ERROR"}
        if len(unique_hashes) <= 1:
            text_identical_files += 1
            continue

        # Compare all pairs (petrenca vs schiekiera, petrenca vs hu_server,
        # schiekiera vs hu_server) and only print when there is a textual diff.
        file_has_text_diff = False

        source_names = list(sources.keys())
        num_sources = len(source_names)

        for i in range(num_sources):
            for j in range(i + 1, num_sources):
                src_a = source_names[i]
                src_b = source_names[j]

                # Skip if one of the contents could not be fetched
                if hashes[src_a] == "ERROR" or hashes[src_b] == "ERROR":
                    continue

                # Skip if byte-identical
                if hashes[src_a] == hashes[src_b]:
                    continue

                diff_lines = print_text_diff(
                    contents[src_a],
                    contents[src_b],
                    label_a=f"{src_a}::{fname}",
                    label_b=f"{src_b}::{fname}",
                    max_lines=80,
                )

                if diff_lines > 0:
                    if not file_has_text_diff:
                        if not any_diff:
                            # First time we encounter any textual difference, print a blank line
                            # to visually separate from the header.
                            print()
                        print(f"  Textual differences in {fname}:")
                        file_has_text_diff = True
                        any_diff = True

        if file_has_text_diff:
            text_diff_files += 1
        else:
            # Binary differences but no visible textual differences
            text_identical_files += 1

    if not any_diff:
        print("  No textual differences in files present in all three locations.")
    else:
        total_compared = len(common_filenames)
        print(
            f"\nSummary: {total_compared} files compared, "
            f"{text_diff_files} with textual differences, "
            f"{text_identical_files} without textual differences."
        )


if __name__ == "__main__":
    main()
