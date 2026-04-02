# """
# Implement Simplified FaST

# Implements FaST (Frame-based Similarity Technique) from Rodrigues et al., 2022.

# Loads crash_reports.jsonl, normalizes frames, builds frame strings,
# computes similarities, and clusters crash reports.

# Usage:
#     # pip install python-Levenshtein
#     python implement_fast.py
# """

# import json
# import os
# import re
# from collections import defaultdict

# try:
#     import Levenshtein
# except ImportError:
#     print("Installing python-Levenshtein...")
#     os.system("pip install python-Levenshtein")
#     import Levenshtein

# # ── CONFIG ──
# DATA_DIR = "data"
# RESULTS_DIR = "results"
# CRASH_REPORTS_FILE = os.path.join(DATA_DIR, "crash_reports.jsonl")
# FRAME_STRINGS_FILE = os.path.join(RESULTS_DIR, "frame_strings.jsonl")
# CLUSTERS_FILE = os.path.join(RESULTS_DIR, "fast_clusters.json")
# SIMILARITY_SAMPLE_FILE = os.path.join(RESULTS_DIR, "similarity_samples.json")

# TOP_N_FRAMES = 5           # Number of top frames to use
# SIMILARITY_THRESHOLD = 0.6  # Default threshold (paper recommends 0.6)

# os.makedirs(RESULTS_DIR, exist_ok=True)


# #Loading Data

# def load_crash_reports():
#     """
#     Load crash_reports.jsonl, keep only reports with status=ok and frames.
#     """
#     reports = []
#     skipped = 0
#     with open(CRASH_REPORTS_FILE, "r") as f:
#         for line in f:
#             line = line.strip()
#             if not line:
#                 continue
#             record = json.loads(line)
#             if record.get("status") != "ok":
#                 skipped += 1
#                 continue
#             if not record.get("frames"):
#                 skipped += 1
#                 continue
#             reports.append(record)

#     print(f"  Loaded {len(reports)} crash reports (skipped {skipped} empty/failed)")
#     return reports



# #  NORMALIZING FRAMES


# def normalize_frame(function_name):
#     """
#     Normalize a frame's function name:
#     - Strip hex addresses (@0x...)
#     - Remove DLL offsets (xul.dll@0x...)
#     - Remove template parameters (<T>, <...>)
#     - Remove parentheses ()
#     - Lowercase everything
#     - Collapse whitespace
#     """
#     if not function_name:
#         return ""

#     name = function_name

#     # Remove hex addresses
#     name = re.sub(r'@0x[0-9a-fA-F]+', '', name)

#     # Remove DLL offsets
#     name = re.sub(r'\w+\.dll@0x[0-9a-fA-F]+', '', name)
#     name = re.sub(r'\w+\.so[.\d]*@0x[0-9a-fA-F]+', '', name)
#     name = re.sub(r'\w+\.dylib@0x[0-9a-fA-F]+', '', name)

#     # Remove template parameters (handle nested by repeating)
#     prev = ""
#     while prev != name:
#         prev = name
#         name = re.sub(r'<[^<>]*>', '', name)

#     # Remove parentheses and their contents
#     name = re.sub(r'\([^)]*\)', '', name)

#     # Lowercase
#     name = name.lower().strip()

#     # Collapse whitespace
#     name = re.sub(r'\s+', ' ', name).strip()

#     return name



# # Build Frame Strings based on top N frames


# def build_frame_string(report, top_n=TOP_N_FRAMES):
#     """
#     Take the top N frames, normalize each function name,
#     join with ' | ' separator.
#     This is the string FaST compares using Levenshtein distance.
#     """
#     frames = report.get("frames", [])
#     normalized = []
#     for i in range(min(top_n, len(frames))):
#         func = frames[i].get("function", "")
#         norm = normalize_frame(func)
#         if norm:
#             normalized.append(norm)
#     return " | ".join(normalized)


# def build_all_frame_strings(reports):
#     """
#     Build frame strings for all reports.
#     Stores the frame string inside each report dict.
#     Also saves to JSONL for inspection.
#     """
#     with open(FRAME_STRINGS_FILE, "w") as f:
#         for r in reports:
#             fs = build_frame_string(r)
#             r["_frame_string"] = fs
#             record = {
#                 "crash_id": r["crash_id"],
#                 "signature": r["signature"],
#                 "true_bug_ids": r.get("true_bug_ids", []),
#                 "frame_string": fs,
#             }
#             f.write(json.dumps(record) + "\n")

#     print(f"  Built frame strings for {len(reports)} reports")
#     print(f"  Saved -> {FRAME_STRINGS_FILE}")
#     return reports


# # Computing FaST Similarity


# def fast_similarity(str_a, str_b):
#     """
#     FaST similarity = 1 - (levenshtein_distance / max_length).
#     Returns value in [0.0, 1.0].
#     1.0 = identical, 0.0 = completely different.
#     """
#     if not str_a and not str_b:
#         return 1.0
#     if not str_a or not str_b:
#         return 0.0
#     max_len = max(len(str_a), len(str_b))
#     dist = Levenshtein.distance(str_a, str_b)
#     return 1.0 - (dist / max_len)


# def show_similarity_samples(reports, n_samples=20):
#     """
#     Pick some pairs and show their similarity scores.
#     Helps verify normalization and similarity are working correctly.
#     """
#     import random
#     random.seed(42)

#     samples = []

#     # Pick some same-bug pairs
#     bug_groups = defaultdict(list)
#     for r in reports:
#         for bid in r.get("true_bug_ids", []):
#             bug_groups[bid].append(r)

#     same_bug_pairs = []
#     for bid, group in bug_groups.items():
#         if len(group) >= 2:
#             for i in range(min(3, len(group))):
#                 for j in range(i + 1, min(4, len(group))):
#                     same_bug_pairs.append((group[i], group[j], bid))

#     # Pick some different-bug pairs
#     if len(reports) > 1:
#         diff_pairs = []
#         for _ in range(30):
#             a, b = random.sample(reports, 2)
#             a_bugs = set(a.get("true_bug_ids", []))
#             b_bugs = set(b.get("true_bug_ids", []))
#             if not a_bugs & b_bugs:
#                 diff_pairs.append((a, b))

#     print(f"\n  SAME-BUG PAIRS (should have HIGH similarity):")
#     count = 0
#     for a, b, bid in same_bug_pairs[:10]:
#         sim = fast_similarity(a["_frame_string"], b["_frame_string"])
#         print(f"    sim={sim:.3f}  Bug #{bid}")
#         print(f"      A: {a['_frame_string'][:80]}")
#         print(f"      B: {b['_frame_string'][:80]}")
#         samples.append({
#             "type": "same_bug", "bug_id": bid, "similarity": sim,
#             "frame_a": a["_frame_string"][:100], "frame_b": b["_frame_string"][:100],
#         })
#         count += 1

#     print(f"\n  DIFFERENT-BUG PAIRS (should have LOW similarity):")
#     for a, b in diff_pairs[:10]:
#         sim = fast_similarity(a["_frame_string"], b["_frame_string"])
#         print(f"    sim={sim:.3f}  Bugs {a.get('true_bug_ids',[])} vs {b.get('true_bug_ids',[])}")
#         print(f"      A: {a['_frame_string'][:80]}")
#         print(f"      B: {b['_frame_string'][:80]}")
#         samples.append({
#             "type": "diff_bug", "similarity": sim,
#             "frame_a": a["_frame_string"][:100], "frame_b": b["_frame_string"][:100],
#         })

#     with open(SIMILARITY_SAMPLE_FILE, "w") as f:
#         json.dump(samples, f, indent=2)
#     print(f"\n  Saved similarity samples -> {SIMILARITY_SAMPLE_FILE}")



# # FaST CLUSTERING

# def cluster_with_fast(reports, threshold=SIMILARITY_THRESHOLD):
#     """
#     Greedy single-pass clustering:
#     For each report, compare its frame string against existing cluster
#     centroids. Assign to the best match if similarity >= threshold,
#     otherwise create a new cluster.
#     """
#     clusters = {}
#     cluster_id = 0

#     for report in reports:
#         frame_str = report["_frame_string"]

#         best_cid = None
#         best_sim = 0.0

#         for cid, info in clusters.items():
#             sim = fast_similarity(frame_str, info["centroid"])
#             if sim >= threshold and sim > best_sim:
#                 best_cid = cid
#                 best_sim = sim

#         if best_cid is not None:
#             clusters[best_cid]["reports"].append(report["crash_id"])
#             clusters[best_cid]["signatures"].add(report["signature"])
#             clusters[best_cid]["bug_ids"].update(report.get("true_bug_ids", []))
#         else:
#             cluster_id += 1
#             clusters[cluster_id] = {
#                 "centroid": frame_str,
#                 "reports": [report["crash_id"]],
#                 "signatures": {report["signature"]},
#                 "bug_ids": set(report.get("true_bug_ids", [])),
#             }

#     return clusters


# def save_and_show_clusters(clusters, threshold):
#     """Print cluster summary and save to JSON."""

#     print(f"\n  Total clusters: {len(clusters)}")
#     total_reports = sum(len(c["reports"]) for c in clusters.values())
#     print(f"  Total reports clustered: {total_reports}")

#     # Sort by size (largest first)
#     sorted_clusters = sorted(clusters.items(), key=lambda x: len(x[1]["reports"]), reverse=True)

#     # Categorize clusters
#     multi_sig = []    # clusters that merged multiple signatures
#     multi_bug = []    # clusters with multiple bugs (potential merge errors)
#     single = []       # clusters with 1 signature, 1 bug

#     for cid, info in sorted_clusters:
#         n_reports = len(info["reports"])
#         n_sigs = len(info["signatures"])
#         n_bugs = len(info["bug_ids"])

#         if n_bugs > 1:
#             multi_bug.append((cid, info))
#         elif n_sigs > 1:
#             multi_sig.append((cid, info))
#         else:
#             single.append((cid, info))

#     print(f"\n  Clusters merging multiple signatures (potential split fixes): {len(multi_sig)}")
#     for cid, info in multi_sig[:15]:
#         print(f"    Cluster {cid} ({len(info['reports'])} reports)")
#         print(f"      Bugs: {info['bug_ids']}")
#         print(f"      Signatures merged:")
#         for s in list(info["signatures"])[:5]:
#             print(f"        - {s[:70]}")

#     print(f"\n  Clusters with multiple bugs (potential merge errors): {len(multi_bug)}")
#     for cid, info in multi_bug[:15]:
#         print(f"    Cluster {cid} ({len(info['reports'])} reports)")
#         print(f"      Bugs: {info['bug_ids']}")
#         print(f"      Signatures:")
#         for s in list(info["signatures"])[:5]:
#             print(f"        - {s[:70]}")

#     print(f"\n  Clean clusters (1 sig, 1 bug): {len(single)}")

#     # Save to JSON (convert sets to lists for JSON)
#     save_data = {}
#     for cid, info in clusters.items():
#         save_data[str(cid)] = {
#             "centroid": info["centroid"],
#             "reports": info["reports"],
#             "signatures": list(info["signatures"]),
#             "bug_ids": list(info["bug_ids"]),
#             "n_reports": len(info["reports"]),
#         }

#     out_file = os.path.join(RESULTS_DIR, f"fast_clusters_t{threshold}.json")
#     with open(out_file, "w") as f:
#         json.dump(save_data, f, indent=2)
#     print(f"\n  Saved clusters -> {out_file}")

#     return multi_sig, multi_bug, single



# # Main method execution


# if __name__ == "__main__":
#     print("=" * 70)
#     print("STEP 3: IMPLEMENT FaST")
#     print("=" * 70)

#     # Load crash reports
#     print("\n1. Loading crash reports...")
#     reports = load_crash_reports()

#     # Build frame strings
#     print("\n2. Building normalized frame strings...")
#     reports = build_all_frame_strings(reports)

#     # Show some examples of normalization
#     print("\n  NORMALIZATION EXAMPLES:")
#     for r in reports[:5]:
#         raw_funcs = [f.get("function", "") for f in r["frames"][:TOP_N_FRAMES]]
#         print(f"    Raw:        {raw_funcs}")
#         print(f"    Normalized: {r['_frame_string']}")
#         print()

#     # Show similarity samples
#     print("\n3. Computing similarity samples...")
#     show_similarity_samples(reports)

#     # Run clustering at multiple thresholds
#     thresholds = [0.3, 0.4, 0.5, 0.6, 0.7, 0.8]

#     print(f"\n4. Clustering with FaST at {len(thresholds)} thresholds...")

#     for t in thresholds:
#         print(f"\n{'=' * 70}")
#         print(f"  THRESHOLD = {t}")
#         print(f"{'=' * 70}")
#         clusters = cluster_with_fast(reports, threshold=t)
#         multi_sig, multi_bug, single = save_and_show_clusters(clusters, t)

#     print("\n" + "=" * 70)
#     print("STEP 3 COMPLETE")
#     print("=" * 70)
#     print(f"  Frame strings saved: {FRAME_STRINGS_FILE}")
#     print(f"  Clusters saved for thresholds: {thresholds}")
#     for t in thresholds:
#         print(f"    results/fast_clusters_t{t}.json")
#     print(f"  Similarity samples: {SIMILARITY_SAMPLE_FILE}")
#     print(f"\n  Next: run Step 4 to compute evaluation metrics.")