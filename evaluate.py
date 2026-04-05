"""
Evaluate FaST Clusters:
Usage: python3 evaluate.py

Not all the portions of this code are used in the final evaluation, but they are left here for reference and potential future use.
"""

import json
import os
import csv
from collections import defaultdict

#intial setup: define file paths and load data
DATA_DIR = "data"
RESULTS_DIR = "results"
GROUND_TRUTH_FILE = os.path.join(DATA_DIR, "ground_truth.csv")
CRASH_REPORTS_FILE = os.path.join(DATA_DIR, "crash_reports.jsonl")
EVALUATION_FILE = os.path.join(RESULTS_DIR, "evaluation.csv")
EVALUATION_DETAIL_FILE = os.path.join(RESULTS_DIR, "evaluation_detail.json")

os.makedirs(RESULTS_DIR, exist_ok=True)



# DATA LOADING
def load_ground_truth():
    """Load ground_truth.csv into sig -> set of bug_ids mapping."""
    sig_to_bugs = defaultdict(set)
    with open(GROUND_TRUTH_FILE, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            sig_to_bugs[row["crash_signature"]].add(row["true_bug_id"])
    return sig_to_bugs


def load_crash_reports():
    """Load crash reports, keep only status=ok with frames."""
    reports = []
    skipped = 0
    with open(CRASH_REPORTS_FILE, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            record = json.loads(line)
            if record.get("status") != "ok" or not record.get("frames"):
                skipped += 1
                continue
            reports.append(record)
    print(f"  Loaded {len(reports)} crash reports (skipped {skipped})")
    return reports


def load_fast_clusters(threshold):
    """Load FaST clusters from Step 3 output."""
    path = os.path.join(RESULTS_DIR, f"fast_clusters_t{threshold}.json")
    if not os.path.exists(path):
        print(f"  WARNING: {path} not found. Skipping threshold {threshold}.")
        return None
    with open(path) as f:
        return json.load(f)


def assign_primary_bug_id(reports, sig_to_bugs):
    """Assign a primary bug ID to each report for evaluation."""
    tagged = []
    for r in reports:
        sig = r["signature"]
        gt_bugs = sig_to_bugs.get(sig, set())
        report_bugs = set(str(b) for b in r.get("true_bug_ids", []))
        bug_ids = gt_bugs | report_bugs
        if not bug_ids:
            continue
        r["primary_bug_id"] = sorted(bug_ids)[0]
        r["all_bug_ids"] = list(bug_ids)
        tagged.append(r)
    print(f"  Reports with bug IDs: {len(tagged)}")
    return tagged


def build_socorro_clusters(reports):
    """Group reports by their Socorro signature (baseline clustering)."""
    sig_groups = defaultdict(list)
    for r in reports:
        sig_groups[r["signature"]].append(r["crash_id"])
    clusters = {}
    for i, (sig, crash_ids) in enumerate(sig_groups.items()):
        clusters[str(i)] = {
            "reports": crash_ids,
            "signatures": [sig],
            "bug_ids": list(set(
                r["primary_bug_id"] for r in reports if r["crash_id"] in crash_ids
            )),
        }
    return clusters


def build_lookups(reports):
    """Build crash_id -> bug_id and bug_id -> [crash_ids] mappings."""
    crash_to_bug = {}
    bug_to_crashes = defaultdict(list)
    for r in reports:
        crash_to_bug[r["crash_id"]] = r["primary_bug_id"]
        bug_to_crashes[r["primary_bug_id"]].append(r["crash_id"])
    return crash_to_bug, bug_to_crashes



# METRIC 1: PURITY (Amigo et al., 2009))    


def compute_purity(clusters, crash_to_bug, N):
    """
    Purity (Zhao & Karypis, 2001):
    For each cluster, find the most common category and count
    how many items belong to it. Sum over all clusters, divide by N.
    """
    total_correct = 0

    for cid, info in clusters.items():
        crash_ids = info["reports"]
        category_counts = defaultdict(int)
        for crash_id in crash_ids:
            bug_id = crash_to_bug.get(crash_id)
            if bug_id:
                category_counts[bug_id] += 1

        if category_counts:
            total_correct += max(category_counts.values())

    purity = total_correct / N if N > 0 else 0
    return purity



# METRIC 2: INVERSE PURITY (Amigo et al., 2009) - also known as "Inverse Purity" or "Coverage"

def compute_inverse_purity(clusters, crash_to_bug, bug_to_crashes, N):
    """
    Inverse Purity:
    For each category (bug), find the cluster with the most items
    from that category. Sum those max overlaps, divide by N.
    """
    crash_to_cluster = {}
    for cid, info in clusters.items():
        for crash_id in info["reports"]:
            crash_to_cluster[crash_id] = cid

    total_correct = 0

    for bug_id, crash_ids in bug_to_crashes.items():
        cluster_counts = defaultdict(int)
        for crash_id in crash_ids:
            cid = crash_to_cluster.get(crash_id)
            if cid:
                cluster_counts[cid] += 1

        if cluster_counts:
            total_correct += max(cluster_counts.values())

    inverse_purity = total_correct / N if N > 0 else 0
    return inverse_purity


# METRIC 3: PAIRWISE PRECISION & RECALL (Halkidi et al., 2001)

#
# SS = pairs in same cluster AND same category
# SD = pairs in same cluster AND different category
# DS = pairs in different cluster AND same category
#
# Pairwise Precision = SS / (SS + SD)
#   Of all pairs placed in the same cluster, how many truly share a bug?
#
# Pairwise Recall = SS / (SS + DS)
#   Of all pairs that share a bug, how many are in the same cluster?

def compute_pairwise_metrics(clusters, crash_to_bug):
    """
    Pairwise Precision and Recall (Halkidi et al., 2001).

    Counts pairs of items:
    SS = same cluster, same category (true positive)
    SD = same cluster, different category (false positive)
    DS = different cluster, same category (false negative)
    """
    # Build cluster membership
    crash_to_cluster = {}
    cluster_members = defaultdict(list)
    for cid, info in clusters.items():
        for crash_id in info["reports"]:
            crash_to_cluster[crash_id] = cid
            cluster_members[cid].append(crash_id)

    SS = 0  # same cluster, same category
    SD = 0  # same cluster, different category

    # Count SS and SD by iterating within each cluster
    for cid, members in cluster_members.items():
        for i in range(len(members)):
            for j in range(i + 1, len(members)):
                bug_i = crash_to_bug.get(members[i])
                bug_j = crash_to_bug.get(members[j])
                if bug_i and bug_j:
                    if bug_i == bug_j:
                        SS += 1
                    else:
                        SD += 1

    # Count DS: pairs with same category but different cluster
    # Group by category, then count pairs NOT in same cluster
    category_members = defaultdict(list)
    for crash_id, bug_id in crash_to_bug.items():
        if crash_id in crash_to_cluster:
            category_members[bug_id].append(crash_id)

    DS = 0
    for bug_id, members in category_members.items():
        for i in range(len(members)):
            for j in range(i + 1, len(members)):
                if crash_to_cluster.get(members[i]) != crash_to_cluster.get(members[j]):
                    DS += 1

    pair_precision = SS / (SS + SD) if (SS + SD) > 0 else 0.0
    pair_recall = SS / (SS + DS) if (SS + DS) > 0 else 0.0

    return pair_precision, pair_recall, SS, SD, DS



# F-MEASURE (Van Rijsbergen, 1974)


# def f_measure(precision, recall, alpha=0.5):
#     """
#     Van Rijsbergen's F-measure:
#     F = 1 / (α * (1/P) + (1-α) * (1/R))
#     With α=0.5, this is the harmonic mean.
#     """
#     if precision == 0 or recall == 0:
#         return 0.0
#     return 1.0 / (alpha * (1.0 / precision) + (1.0 - alpha) * (1.0 / recall))


# EVALUATE ONE CLUSTERING


def evaluate_clustering(clusters, crash_to_bug, bug_to_crashes, N, label):
    """Run all metrics on a clustering and return results dict."""
    print(f"\n  {'─' * 60}")
    print(f"  {label}")
    print(f"  {'─' * 60}")
    print(f"  Number of clusters: {len(clusters)}")

    # Purity
    purity = compute_purity(clusters, crash_to_bug, N)
    print(f"\n  Purity:              {purity:.4f}")

    # Inverse Purity
    inv_purity = compute_inverse_purity(
        clusters, crash_to_bug, bug_to_crashes, N
    )
    print(f"  Inverse Purity:      {inv_purity:.4f}")

    # F(Purity, Inverse Purity)
    # f_pur = f_measure(purity, inv_purity)
    # print(f"  F(Purity, InvPur):   {f_pur:.4f}")

    # Pairwise Precision & Recall
    pair_prec, pair_rec, SS, SD, DS = compute_pairwise_metrics(
        clusters, crash_to_bug
    )
    print(f"\n  Pairwise Precision:  {pair_prec:.4f}  (SS={SS}, SD={SD})")
    print(f"  Pairwise Recall:     {pair_rec:.4f}  (SS={SS}, DS={DS})")

    # F(Pairwise)
    # f_pair = f_measure(pair_prec, pair_rec)
    # print(f"  F(Pair Prec, Rec):   {f_pair:.4f}")

    # Count merge and split errors
    crash_to_cluster = {}
    for cid, info in clusters.items():
        for crash_id in info["reports"]:
            crash_to_cluster[crash_id] = cid

    merge_errors = 0
    for cid, info in clusters.items():
        bug_set = set(
            crash_to_bug.get(c) for c in info["reports"]
            if crash_to_bug.get(c)
        )
        if len(bug_set) > 1:
            merge_errors += 1

    bug_to_cluster_set = defaultdict(set)
    for crash_id, bug_id in crash_to_bug.items():
        if crash_id in crash_to_cluster:
            bug_to_cluster_set[bug_id].add(crash_to_cluster[crash_id])
    split_errors = sum(1 for b, cs in bug_to_cluster_set.items() if len(cs) > 1)

    print(f"\n  Merge errors:        {merge_errors}")
    print(f"  Split errors:        {split_errors}")

    return {
        "method": label,
        "clusters": len(clusters),
        "purity": round(purity, 4),
        "inverse_purity": round(inv_purity, 4),
        # "f_purity_inv": round(f_pur, 4),
        "pair_precision": round(pair_prec, 4),
        "pair_recall": round(pair_rec, 4),
        # "f_pairwise": round(f_pair, 4),
        "merge_errors": merge_errors,
        "split_errors": split_errors,
    }


# Main Method

if __name__ == "__main__":
    print("=" * 70)
    print("EVALUATE CLUSTERS")
    print("Metrics: Purity, Inverse Purity, Pairwise Precision & Recall")
    print("=" * 70)

    # Load data
    print("\nLoading data...")
    sig_to_bugs = load_ground_truth()
    reports = load_crash_reports()
    reports = assign_primary_bug_id(reports, sig_to_bugs)
    crash_to_bug, bug_to_crashes = build_lookups(reports)
    N = len(reports)

    print(f"  Total items (N): {N}")
    print(f"  Unique categories (bugs): {len(bug_to_crashes)}")

    all_results = []

    # ── Evaluate Socorro (baseline) ──
    socorro_clusters = build_socorro_clusters(reports)
    result = evaluate_clustering(
        socorro_clusters, crash_to_bug, bug_to_crashes, N,
        "Socorro Signatures"
    )
    all_results.append(result)

    # ── Evaluate FaST at multiple thresholds ──
    thresholds = [0.3, 0.4, 0.5, 0.6, 0.7, 0.8]

    for t in thresholds:
        fast_clusters = load_fast_clusters(t)
        if fast_clusters is None:
            continue
        result = evaluate_clustering(
            fast_clusters, crash_to_bug, bug_to_crashes, N,
            f"FaST (t={t})"
        )
        all_results.append(result)

    # ── Comparison Table ──
    print("\n" + "=" * 120)
    print("COMPARISON TABLE")
    print("=" * 120)

    header = (
        f"{'Method':<25} {'Clust':>6}  "
        f"{'Purity':>7} {'InvPur':>7} {'F(P,IP)':>7}  "
        f"{'PairPr':>7} {'PairRe':>7} {'F(Pair)':>7}  "
        f"{'Merge':>6} {'Split':>6}"
    )
    print(header)
    print("─" * 120)

    for r in all_results:
        row = (
            f"{r['method']:<25} {r['clusters']:>6}  "
            f"{r['purity']:>7.4f} {r['inverse_purity']:>7.4f} {r['f_purity_inv']:>7.4f}  "
            f"{r['pair_precision']:>7.4f} {r['pair_recall']:>7.4f} {r['f_pairwise']:>7.4f}  "
            f"{r['merge_errors']:>6} {r['split_errors']:>6}"
        )
        print(row)

    # ── Find best threshold ──
    fast_results = [r for r in all_results if "FaST" in r["method"]]
    if fast_results:
        best_f_pur = max(fast_results, key=lambda x: x["f_purity_inv"])
        best_f_pair = max(fast_results, key=lambda x: x["f_pairwise"])
        print(f"\n  Best FaST by F(Purity, InvPurity):  {best_f_pur['method']} -> {best_f_pur['f_purity_inv']:.4f}")
        print(f"  Best FaST by F(Pairwise):           {best_f_pair['method']} -> {best_f_pair['f_pairwise']:.4f}")

    # ── Save results ──
    with open(EVALUATION_FILE, "w", newline="") as f:
        fields = [
            "method", "clusters",
            "purity", "inverse_purity", "f_purity_inv",
            "pair_precision", "pair_recall", "f_pairwise",
            "merge_errors", "split_errors",
        ]
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(all_results)
    print(f"\n  Results saved -> {EVALUATION_FILE}")

    with open(EVALUATION_DETAIL_FILE, "w") as f:
        json.dump(all_results, f, indent=2)
    print(f"  Detail saved -> {EVALUATION_DETAIL_FILE}")

    print("\n" + "=" * 70)

    print("=" * 70)
