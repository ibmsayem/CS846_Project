from __future__ import annotations

import argparse
import json
import sys
import time
from collections import defaultdict
from typing import Dict, List, Tuple

from data_clean import load_crash_reports
from fast_algorithm import (
    DFIndex,
    StackTrace,
    prepare_stack_trace,
    fast_similarity,
    bucket_similarity,
    find_duplicates,
)


# Coarse pass: group reports by Socorro signature


def group_by_signature(reports: List[dict]) -> Dict[str, List[dict]]:
    """Group crash reports by their Socorro ``signature`` field.

    This is a cheap pre-filter; FaST is only applied *within* each group.
    """
    groups: Dict[str, List[dict]] = defaultdict(list)
    for r in reports:
        groups[r.get("signature", "<none>")].append(r)
    return dict(groups)


# Core deduplication logic: cluster traces within each signature group using the paper's bucket similarity (Section 4.2):
# For each new report q, we compute:
#   sim'(q, B) = max_{c ∈ B} sim(q, c)
# for every existing bucket B.  The report is assigned to the bucket
# with the highest sim' provided it exceeds the threshold.
# Otherwise, a new bucket is created.


def deduplicate_group(traces: List[StackTrace],
                      gamma: float,
                      threshold: float) -> List[List[StackTrace]]:
    """Cluster traces within a single signature group.

    Uses the paper's bucket similarity
        sim'(q, B) = max_{c ∈ B} sim(q, c)

    Each new trace is assigned to the bucket with the HIGHEST sim'
    that exceeds *threshold*.  If no bucket qualifies, a new one is
    created.

    Returns a list of buckets (each bucket = list of StackTrace).
    """
    if len(traces) <= 1:
        return [traces]

    buckets: List[List[StackTrace]] = []

    for st in traces:
        best_sim = -2.0
        best_bucket_idx = -1

        for bi, bucket in enumerate(buckets):
            # sim'(q, B) = max_{c ∈ B} sim(q, c) — Eq from Section 4.2
            sim_prime = bucket_similarity(st, bucket, gamma)
            if sim_prime > best_sim:
                best_sim = sim_prime
                best_bucket_idx = bi

        if best_sim >= threshold and best_bucket_idx >= 0:
            buckets[best_bucket_idx].append(st)
        else:
            buckets.append([st])

    return buckets
