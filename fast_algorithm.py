"""
fast_algorithm.py
Implementation of the FaST similarity algorithm as described in:
"FaST: Fast and Accurate Stack Trace Similarity for Software Failure Deduplication"

References
All equation / algorithm numbers refer to the MSR '22 paper above.
Source code of the original FaST: https://github.com/irving-muller/FaST
"""

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
        Normalised subroutine / function name (the identifier *f*).
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

    Attributes are dicussed below
  
    uuid(str): Unique identifier of the crash report.
    signature(str): Socorro signature (used for coarse grouping, not by FaST itself).
    sorted_frames (list[FrameEntry]): Frames sorted by (frame_id, position) ascending input
        format required by Algorithm 1.
    weight_sum (float):
        Σ w(f_p) for every frame in this trace.  Pre computed so that
        the normalization denominator (line 23) can be looked up in O(1).
    """
    uuid: str
    signature: str
    sorted_frames: List[FrameEntry] = field(default_factory=list)
    weight_sum: float = 0.0


# Document-Frequency Index
#
# df(f) = number of stack traces in S that contain at least one frame
#         with identifier f  (used in Equation 1).
# |S|   = total number of stack traces in the repository.
# This is built once from the cleaned crash reports and then used for all
# subsequent similarity computations.

class DFIndex:
    """Stores df(f) for every subroutine identifier in the repository."""

    def __init__(self) -> None:
        self._df: Counter = Counter()
        self._total: int = 0

    @property
    def total_traces(self) -> int:
        """Return |S|: the total number of stack traces."""
        return self._total

    def df(self, frame_id: str) -> int:
        """Return df(f): the number of traces containing *frame_id*."""
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



# Equation 1: Frame Weight: w(f_p)
#
#   w(f_p) = 1/p^α  ×  e^{-β · df(f) / |S|}
#
# • First factor:  higher weights for frames closer to the top.
# • Second factor: lower weights for frequently occurring subroutines.
# • α, β ∈ ℝ₊ are hyper-parameters.


def frame_weight(position: int,
                 df: int,
                 total_traces: int,
                 alpha: float = 1.0,
                 beta: float = 1.0) -> float:
    """Compute w(f_p) per Equation 1."""
    position_factor  = 1.0 / (position ** alpha)
    frequency_factor = math.exp(-beta * df / total_traces) if total_traces > 0 else 1.0
    return position_factor * frequency_factor



# Equation 2: Gap Value: gap(f_p) = w(f_p)
#
def gap_value(w: float) -> float:
    """Compute gap(f_p) = w(f_p)  (Equation 2)."""
    return w

# Equation 3 : Match Value: match(q_u, c_v)
#
#   match(q_u, c_v) = (w(q_u) + w(c_v)) × diff(u, v)
#
# where diff(u, v) = e^{-γ |u − v|}
# • Uses the SUM of frame weights (unlike TraceSim which uses the MAX).
# • diff(·) penalises position discrepancy between matched frames.
# • γ ∈ ℝ₊ regulates the impact of position difference.


def diff(u: int, v: int, gamma: float = 0.1) -> float:
    """diff(u, v) = e^{-γ |u − v|}"""
    return math.exp(-gamma * abs(u - v))


def match_value(w_q: float, w_c: float,
                pos_q: int, pos_c: int,
                gamma: float = 0.1) -> float:
    """match(q_u, c_v) = (w(q_u) + w(c_v)) × diff(u, v)  (Equation 3)."""
    return (w_q + w_c) * diff(pos_q, pos_c, gamma)


# Preprocessing: Build StackTrace objects
#
# Paper (Section 2.1): "As input, the similarity algorithm receives two lists sorted by frame id and position in ascending order. Such sort is executed only once right after stack trace creation."


def prepare_stack_trace(report: dict,
                        df_index: DFIndex,
                        alpha: float = 1.0,
                        beta: float = 1.0) -> StackTrace:
    """Convert a cleaned crash-report dict into a StackTrace.

    Steps (following the paper):
    1. Assign each frame a 1-based position (top = 1).
    2. Compute its weight w(f_p) via Equation 1.
    3. Sort the frame list by (frame_id, position) ascending.
    4. Pre-compute Σ w(f_p) for normalisation (line 23).
    """
    entries: List[FrameEntry] = []
    total = df_index.total_traces

    for idx, fid in enumerate(report["frames"]):
        pos = idx + 1                                          # 1-based
        w = frame_weight(pos, df_index.df(fid), total, alpha, beta)
        entries.append(FrameEntry(frame_id=fid, position=pos, weight=w))

    # Paper prerequisite: sort by (frame_id, position) ascending
    entries.sort(key=lambda e: (e.frame_id, e.position))
    weight_sum = sum(e.weight for e in entries)

    return StackTrace(
        uuid=report["uuid"],
        signature=report.get("signature", ""),
        sorted_frames=entries,
        weight_sum=weight_sum,
    )



# Algorithm 1: FaST Similarity
#
# Two pointers (i, j) walk through Q and C (both sorted by frame_id,
# position).  At each step, exactly one of three cases applies:
#
#   q == c  →  MATCH: sim += match(q_u, c_v);  advance both pointers
#   q  < c  →  GAP:   sim -= gap(q_u);         advance i
#   q  > c  →  GAP:   sim -= gap(c_v);         advance j
#
# After the loop, remaining frames in either list become gaps.
#
# Normalisation (Section 2.3, line 23):
#   return sim / (Σ_{q_u ∈ Q} w(q_u) + Σ_{c_v ∈ C} w(c_v))
#
# Result range: [-1.0, +1.0]
#   +1.0  best case: all frames match at identical positions
#   -1.0  worst case: zero shared identifiers


def fast_similarity(q: StackTrace, c: StackTrace,
                    gamma: float = 0.1) -> float:
    """Compute the FaST similarity score between traces *q* and *c*.

    Implements Algorithm 1 from the paper verbatim.
    Runs in O(m + n) time where m = |Q|, n = |C|.

    Returns
    -------
    float in [-1.0, +1.0]
    """
    Q = q.sorted_frames
    C = c.sorted_frames

    if not Q or not C:
        return -1.0

    # Line 1-3: initialisation
    sim = 0.0
    i = 0
    j = 0
    m = len(Q)
    n = len(C)

    # Line 4-16: main two-pointer loop
    while i < m and j < n:
        # Line 5-6: read current frames
        q_u = Q[i]          # q is frame_id, u is position
        c_v = C[j]          # c is frame_id, v is position

        if q_u.frame_id == c_v.frame_id:
            # Line 7-10: MATCH alignment
            sim += match_value(q_u.weight, c_v.weight,
                               q_u.position, c_v.position,
                               gamma)
            i += 1
            j += 1

        elif q_u.frame_id < c_v.frame_id:
            # Line 11-13: Q[i] has no partner in C → gap
            sim -= gap_value(q_u.weight)
            i += 1

        else:
            # Line 14-16: C[j] has no partner in Q → gap
            sim -= gap_value(c_v.weight)
            j += 1

    # Line 17-19: remaining frames in Q → gaps
    while i < m:
        sim -= gap_value(Q[i].weight)
        i += 1

    # Line 20-22: remaining frames in C → gaps
    while j < n:
        sim -= gap_value(C[j].weight)
        j += 1

    # Line 23: normalisation
    #   return sim / (Σ w(q_u) + Σ w(c_v))
    #
    # The denominator equals (W_Q + W_C) which we pre-computed.
    denom = q.weight_sum + c.weight_sum
    if denom == 0.0:
        return 0.0

    score = sim / denom
    return max(-1.0, min(1.0, score))       # clamp for float safety



# Section 4.2: Bucket Similarity
#
# "The similarity between q and a bucket B is defined as:
#    sim'(q, B) = max_{c ∈ B} sim(q, c)"
#
# This is used by the evaluation methodology AND by our deduplication
# pipeline to decide which bucket a new report belongs to.


def bucket_similarity(query: StackTrace,
                      bucket: List[StackTrace],
                      gamma: float = 0.1) -> float:
    """sim'(q, B) = max_{c ∈ B} sim(q, c)  — Section 4.2."""
    if not bucket:
        return -1.0
    return max(fast_similarity(query, c, gamma) for c in bucket)



# Batch Helpers


def compute_similarity_matrix(traces: List[StackTrace],
                              gamma: float = 0.1) -> List[List[float]]:
    """Compute the full N×N pairwise similarity matrix."""
    n = len(traces)
    matrix = [[0.0] * n for _ in range(n)]
    for i in range(n):
        matrix[i][i] = 1.0
        for j in range(i + 1, n):
            s = fast_similarity(traces[i], traces[j], gamma)
            matrix[i][j] = s
            matrix[j][i] = s
    return matrix


def find_duplicates(query: StackTrace,
                    repository: List[StackTrace],
                    gamma: float = 0.1,
                    top_k: int = 10) -> List[Tuple[float, StackTrace]]:
    """Rank *repository* traces by FaST similarity to *query*.

    Returns the top-k most similar (score, StackTrace) pairs, sorted
    by descending similarity.
    """
    scored = []
    for st in repository:
        if st.uuid == query.uuid:
            continue
        s = fast_similarity(query, st, gamma)
        scored.append((s, st))
    scored.sort(key=lambda x: x[0], reverse=True)
    return scored[:top_k]

if __name__ == "__main__":
    # ---- Figure 3 example: Q = adca, C = daccb --------------------------
    #  Sorted Q: a1, a4, c3, d2
    #  Sorted C: a2, b5, c3, c4, d1
    #  Expected alignment (from Figure 3e):
    #    MATCH(a1, a2), GAP(a4), GAP(b5), MATCH(c3, c3), GAP(c4), MATCH(d2, d1)
    print("=" * 60)
    print("  Self-test: Figure 3 from the FaST paper")
    print("=" * 60)

    reports = [
        {"uuid": "Q", "signature": "test",
         "frames": ["a", "d", "c", "a"]},       # adca
        {"uuid": "C", "signature": "test",
         "frames": ["d", "a", "c", "c", "b"]},  # daccb
    ]

    idx = DFIndex().build(reports)
    st_q = prepare_stack_trace(reports[0], idx, alpha=1.0, beta=1.0)
    st_c = prepare_stack_trace(reports[1], idx, alpha=1.0, beta=1.0)

    print("\nQ sorted frames (frame_id, position, weight):")
    for e in st_q.sorted_frames:
        print(f"  {e.frame_id}_{e.position}  w={e.weight:.4f}")
    print(f"  W_Q = {st_q.weight_sum:.4f}")

    print("\nC sorted frames (frame_id, position, weight):")
    for e in st_c.sorted_frames:
        print(f"  {e.frame_id}_{e.position}  w={e.weight:.4f}")
    print(f"  W_C = {st_c.weight_sum:.4f}")

    sim = fast_similarity(st_q, st_c, gamma=0.1)
    print(f"\nFaST similarity(Q, C) = {sim:.4f}")

    # ---- Section 2.3 normalization example -------------------------------
    # ST1(a,b,a,a,c) vs ST2(d,d,e): zero shared frames → must be -1.0
    print("\n" + "=" * 60)
    print("  Self-test: Section 2.3 normalization example")
    print("=" * 60)

    reports2 = [
        {"uuid": "ST1", "signature": "t", "frames": ["a", "b", "a", "a", "c"]},
        {"uuid": "ST2", "signature": "t", "frames": ["d", "d", "e"]},
    ]
    idx2 = DFIndex().build(reports2)
    st1 = prepare_stack_trace(reports2[0], idx2, alpha=1.0, beta=1.0)
    st2 = prepare_stack_trace(reports2[1], idx2, alpha=1.0, beta=1.0)

    sim12 = fast_similarity(st1, st2, gamma=0.1)
    print(f"\n  sim(ST1, ST2) = {sim12:.4f}   (expected: -1.0000)")
    print(f"  W_ST1 = {st1.weight_sum:.4f}  W_ST2 = {st2.weight_sum:.4f}")
