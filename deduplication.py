from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass, field
from typing import Dict, List, Tuple



# Data Structures


@dataclass
class FrameEntry:
    """A single frame prepared for the FaST alignment.

    Attributes

    frame_id : str
        Normalized subroutine/function name (the identifier *f*).
    position : int
        1-based position from the top of the stack trace (*p*).
        Top-of-stack = 1.
    weight : float
        Pre-computed frame weight w(f_p) per Equation 1.
    """
    frame_id: str
    position: int
    weight: float = 0.0


@dataclass
class StackTrace:
    """A fully preprocessed stack trace ready for FaST comparison.

    Attributes

    uuid : str
        Unique identifier of the crash report.
    signature : str
        Socorro signature (used for coarse grouping, not by FaST itself).
    sorted_frames : list[FrameEntry]
        Frames sorted by (frame_id, position) ascending the input
        format required by Algorithm 1.
    weight_sum : float
        Σ w(f_p) for every frame in this trace.  Pre-computed so that
        the normalization denominator (line 23) can be looked up in O(1).
    """
    uuid: str
    signature: str
    sorted_frames: List[FrameEntry] = field(default_factory=list)
    weight_sum: float = 0.0

# Preprocessing
# Document-Frequency Index
#
# df(f) = number of stack traces in S that contain at least one frame
#         with identifier f  (used in Equation 1).
# |S|   = total number of stack traces in the repository.
# This is built once from the cleaned crash reports and then used for all subsequent similarity computations.

class DFIndex:
    """Stores df(f) for every subroutine identifier in the repository."""

    def __init__(self) -> None:
        self._df: Counter = Counter()
        self._total: int = 0

    @property
    def total_traces(self) -> int:
        """Return |S| — the total number of stack traces."""
        return self._total

    def df(self, frame_id: str) -> int:
        """Return df(f) — the number of traces containing *frame_id*."""
        return self._df.get(frame_id, 0)

    def build(self, reports: List[dict]) -> "DFIndex":
        """Build the index from cleaned crash reports.

        Each report must have a ``"frames"`` key (list of str).
        df counts each identifier at most once per report (set semantics).
        """
        self._total = len(reports)
        self._df.clear()
        for r in reports:
            unique_ids = set(r["frames"])   # presence, not count
            for fid in unique_ids:
                self._df[fid] += 1
        return self