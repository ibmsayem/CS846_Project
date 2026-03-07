# This file is for cleaning and preprocessing the crash data downloaded from Socorro.
# It reads the raw JSONL file, extracts relevant fields, and outputs a cleaned CSV file for analysis.

import numpy as np
# import pandas as pd
import re





# records = []

# with open('test.jsonl', 'r') as f:
#     for lineno, line in enumerate(f, 1):
#         line  = line.strip()
#         if not line:
#             continue  # Skip empty lines
#         try:
#             records.append(json.loads(line))
#         except json.JSONDecodeError as e:
#             print(f"Error decoding JSON on line {lineno}: {e}")

# print(f"Total records read: {len(records)}")

"""
data_cleaning.py

Load Mozilla Socorro crash reports from a JSONL file, extract stack traces
from the crashing thread, clean / normalize frame identifiers

Each crash report is reduced to a lightweight dict:
    {
        "uuid":       str,
        "signature":  str,
        "frames":     List[str],   # ordered from top (index 0) to bottom
    }
"""

import json
import re
from typing import List, Dict, Optional, Iterator

# 
# Frame‑name cleaning helpers
# 

# Regex to strip template parameters   e.g.  foo<int, bar>  →  foo
_TEMPLATE_RE = re.compile(r"<[^>]*>")

# Regex to strip function arguments     e.g.  foo(int x)     →  foo
_ARGS_RE = re.compile(r"\(.*\)")

# Regex to collapse whitespace
_WS_RE = re.compile(r"\s+")

# Hex‑only names like 0x7ffd107ee394 (unresolved addresses)
_HEX_RE = re.compile(r"^(0x)?[0-9a-fA-F]+$")

# Compiler‑generated / anonymous symbols we want to drop
_ANON_RE = re.compile(
    r"^(\?\?|__imp_|__cxa_|_start$|__libc_start|_dl_|<unknown)",
    re.IGNORECASE,
)


def clean_frame_name(function: Optional[str],
                     module: Optional[str]) -> Optional[str]:
    """Return a normalised identifier for a single stack frame.

    * If the function name is missing or looks like a raw address we try
      to fall back to ``module!offset`` so the frame still carries *some*
      information.
    * Template parameters and argument lists are stripped so that
      ``foo<int>(bar)`` and ``foo<float>(baz)`` map to the same id.
    * Returns ``None`` when the frame should be dropped entirely (e.g. no
      useful information at all).
    """
    if function and not _HEX_RE.match(function):
        name = function.strip()
        name = _TEMPLATE_RE.sub("", name)
        name = _ARGS_RE.sub("", name)
        name = _WS_RE.sub(" ", name).strip()
        if _ANON_RE.match(name):
            return None
        return name if name else None

    # Fallback: use module name when function is unavailable
    if module and not _HEX_RE.match(module):
        return module.strip()

    return None  # truly unresolvable – skip this frame



# Stack‑trace extraction


def extract_frames(processed_crash: dict,
                   max_frames: int = 0) -> List[str]:
    """Extract the cleaned frame list from a processed crash payload.

    Frames come from the *crashing thread* (``crashing_thread`` index).
    Each returned string is the normalised subroutine identifier.

    Parameters
    ----------
    processed_crash : dict
        The ``processed_crash`` object from the JSONL record.
    max_frames : int, optional
        If > 0, keep only the first *max_frames* frames (closest to
        the crash point).  0 means keep all.

    Returns
    -------
    list of str
        Cleaned frame identifiers, top of stack first.
    """
    json_dump = processed_crash.get("json_dump", {})
    threads = json_dump.get("threads", [])
    crashing_idx = processed_crash.get("crashing_thread", 0)

    if not threads:
        return []

    if isinstance(crashing_idx, int) and 0 <= crashing_idx < len(threads):
        thread = threads[crashing_idx]
    else:
        thread = threads[0]

    raw_frames = thread.get("frames", [])
    cleaned: List[str] = []

    for fr in raw_frames:
        name = clean_frame_name(fr.get("function"), fr.get("module"))
        if name is not None:
            cleaned.append(name)

    if max_frames > 0:
        cleaned = cleaned[:max_frames]

    return cleaned



# JSONL loader


def iter_crash_reports(jsonl_path: str,
                       max_frames: int = 0) -> Iterator[Dict]:
    """Yield cleaned crash‑report dicts from *jsonl_path*.

    Each yielded dict has keys ``uuid``, ``signature``, and ``frames``.
    Reports whose stack trace is empty after cleaning are silently skipped.

    Parameters
    ----------
    jsonl_path : str
        Path to the ``processed_crashes.jsonl`` file.
    max_frames : int, optional
        Forwarded to :func:`extract_frames`.
    """
    with open(jsonl_path, "r", encoding="utf-8") as fh:
        for line_no, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                print(f"[WARN] skipping malformed JSON on line {line_no}")
                continue

            if not record.get("ok", False):
                continue

            pc = record.get("processed_crash", {})
            frames = extract_frames(pc, max_frames=max_frames)
            if not frames:
                continue

            yield {
                "uuid": pc.get("uuid", record.get("uuid", f"line-{line_no}")),
                "signature": pc.get("signature", ""),
                "frames": frames,
            }


def load_crash_reports(jsonl_path: str,
                       max_frames: int = 0) -> List[Dict]:
    """Convenience wrapper – returns a list instead of an iterator."""
    return list(iter_crash_reports(jsonl_path, max_frames=max_frames))



# Quick sanity check when run directly

if __name__ == "__main__":
    import sys

    path = sys.argv[1] if len(sys.argv) > 1 else "processed_crashes.jsonl"
    reports = load_crash_reports(path, max_frames=30)
    print(f"Loaded {len(reports)} crash reports with non‑empty stack traces.")
    if reports:
        r = reports[0]
        print(f"\nExample — UUID : {r['uuid']}")
        print(f"           Sig : {r['signature']}")
        print(f"        Frames : {len(r['frames'])}")
        for i, f in enumerate(r["frames"][:10]):
            print(f"          [{i}] {f}")
