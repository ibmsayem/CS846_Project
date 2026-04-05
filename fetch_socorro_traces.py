"""
Fetch Stack Traces from Socorro:
Loads ground_truth.csv, selects interesting signatures (split cases, merge cases, clean cases), then fetches real crash reports with stack frames from Socorro's public API.
    pip install requests
    python fetch_socorro_traces.py
"""

import requests
import json
import csv
import time
import os
from collections import defaultdict

# config and constants
DATA_DIR = "data"
GROUND_TRUTH_FILE = os.path.join(DATA_DIR, "ground_truth.csv")
CRASH_REPORTS_FILE = os.path.join(DATA_DIR, "crash_reports.jsonl")
FETCH_SUMMARY_FILE = os.path.join(DATA_DIR, "fetch_summary.json")

REPORTS_PER_SIGNATURE = 5    # crash reports to fetch per signature
MAX_SPLIT_SIGS = 200         # max signatures from split cases
MAX_MERGE_SIGS = 200         # max signatures from merge cases
MAX_CLEAN_SIGS = 100         # max clean (1:1) signatures as baseline
REQUEST_DELAY = 1.0          # seconds between API calls

os.makedirs(DATA_DIR, exist_ok=True)

# ── MUST-INCLUDE SIGNATURES (your manually verified cases) ──
# PRIORITY_SIGNATURES = {
#     "PRMJ_Now()": [817396],
#     "@0x0 | PRMJ_Now()": [817396],
#     "IncrementalCollectSlice": [817396],
#     "PRMJ_Now": [817396],
#     "@0x0 | PRMJ_Now": [817396],
#     "mozilla::ShouldClearTargets": [1462746],
#     "static bool mozilla::ShouldClearTargets": [1462746],
#     "OOM | large | mozalloc_abort | xul.dll | _PR_NativeRunThread | pr_root": [1725571],
#     "OOM | large | mozalloc_abort | mozalloc_handle_oom | gkrust_shared::oom_hook::hook | std::alloc::rust_oom | webrender_bindings::bindings::wr_state_new": [1531819],
#     "OOM | large | mozalloc_abort | mozalloc_handle_oom | moz_xmalloc | std::basic_string<T>::_Reallocate_grow_by<T>": [1626318],
#     "OOM | large | mozalloc_abort | moz_xmalloc | mozilla::SPSCRingBufferBase<T>::SPSCRingBufferBase": [1757618],
# }



# SELECT WHICH SIGNATURES TO FETCH


def load_ground_truth():
    """Load ground_truth.csv and build lookup dicts."""
    gt_rows = []
    with open(GROUND_TRUTH_FILE, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            gt_rows.append(row)

    sig_to_bugs = defaultdict(set)
    bug_to_sigs = defaultdict(list)

    for row in gt_rows:
        sig = row["crash_signature"]
        bug_id = row["true_bug_id"]
        sig_to_bugs[sig].add(bug_id)
        if sig not in bug_to_sigs[bug_id]:
            bug_to_sigs[bug_id].append(sig)

    # Also add priority signatures to the mappings
    # for sig, bug_ids in PRIORITY_SIGNATURES.items():
    #     for bid in bug_ids:
    #         sig_to_bugs[sig].add(str(bid))
    #         if sig not in bug_to_sigs[str(bid)]:
    #             bug_to_sigs[str(bid)].append(sig)

    # return gt_rows, sig_to_bugs, bug_to_sigs


def select_signatures(sig_to_bugs, bug_to_sigs):
    """
    Pick signatures to fetch, prioritizing:
    0. Priority signatures (always included)
    1. Split cases (1 bug -> multiple sigs)
    2. Merge cases (1 sig -> multiple bugs)
    3. Clean cases (1 sig <-> 1 bug)
    """
    # selected = set(PRIORITY_SIGNATURES.keys())
    print(f"  Priority signatures (always included): {len(selected)}")

    split_sigs = set()
    merge_sigs = set()
    clean_sigs = set()

    # ── Split cases: bugs with multiple signatures ──
    split_bugs = {bid: sigs for bid, sigs in bug_to_sigs.items() if len(sigs) > 1}
    for bid, sigs in sorted(split_bugs.items(), key=lambda x: len(x[1]), reverse=True):
        for sig in sigs:
            if len(split_sigs) < MAX_SPLIT_SIGS:
                split_sigs.add(sig)

    # ── Merge cases: signatures mapped to multiple bugs ──
    for sig, bugs in sorted(sig_to_bugs.items(), key=lambda x: len(x[1]), reverse=True):
        if len(bugs) > 1 and len(merge_sigs) < MAX_MERGE_SIGS:
            merge_sigs.add(sig)

    # ── Clean cases: 1 signature <-> 1 bug (baseline) ──
    for sig, bugs in sig_to_bugs.items():
        if len(bugs) == 1:
            bid = list(bugs)[0]
            if len(bug_to_sigs[bid]) == 1 and len(clean_sigs) < MAX_CLEAN_SIGS:
                clean_sigs.add(sig)

    selected = selected | split_sigs | merge_sigs | clean_sigs

    print(f"  Split case signatures: {len(split_sigs)}")
    print(f"  Merge case signatures: {len(merge_sigs)}")
    print(f"  Clean case signatures: {len(clean_sigs)}")
    print(f"  Total unique to fetch: {len(selected)}")

    return selected, split_sigs, merge_sigs, clean_sigs



# FETCH CRASH IDs FROM SOCORRO SUPERSEARCH

def fetch_crash_ids(signature, n=REPORTS_PER_SIGNATURE):
    """
    Query Socorro SuperSearch for crash report UUIDs for a signature.
    Tries multiple strategies to handle special characters that cause 400 errors.
    """
    import urllib.parse

    base_url = "https://crash-stats.mozilla.org/api/SuperSearch/"
    columns = "&_columns=uuid&_columns=signature&_columns=date&_columns=platform&_columns=product&_columns=version"
    results = f"&_results_number={n}"

    # Build URL manually with proper encoding of just the signature value
    encoded_sig = urllib.parse.quote(signature, safe="")
    url = f"{base_url}?signature=%3D{encoded_sig}{columns}{results}"

    try:
        resp = requests.get(url, timeout=30)

        # Contains match with manually encoded signature
        if resp.status_code == 400:
            url = f"{base_url}?signature=%7E{encoded_sig}{columns}{results}"
            time.sleep(REQUEST_DELAY)
            resp = requests.get(url, timeout=30)

        # Strip ALL special chars, search with just alphanumeric words
        if resp.status_code == 400:
            import re
            # Keep only alphanumeric, underscores, spaces
            cleaned = re.sub(r"[^a-zA-Z0-9_ ]", " ", signature)
            # Get the longest meaningful word (likely the function name)
            words = [w for w in cleaned.split() if len(w) > 3]
            if words:
                # Use the longest word as search term
                search_term = max(words, key=len)
                print(f"    Retrying with keyword: \"{search_term}\"...")
                params = [
                    ("signature", "~" + search_term),
                    ("_columns", "uuid"),
                    ("_columns", "signature"),
                    ("_columns", "date"),
                    ("_columns", "platform"),
                    ("_columns", "product"),
                    ("_columns", "version"),
                    ("_results_number", n),
                ]
                time.sleep(REQUEST_DELAY)
                resp = requests.get(base_url, params=params, timeout=30)

        # Strategy 4: If still failing, try the first pipe-separated part only
        if resp.status_code == 400:
            first_part = signature.split(" | ")[0].strip()
            cleaned_first = re.sub(r"[^a-zA-Z0-9_ ]", " ", first_part)
            words = [w for w in cleaned_first.split() if len(w) > 3]
            if words:
                search_term = max(words, key=len)
                print(f"    Last attempt with: \"{search_term}\"...")
                params = [
                    ("signature", "~" + search_term),
                    ("_columns", "uuid"),
                    ("_columns", "signature"),
                    ("_columns", "date"),
                    ("_columns", "platform"),
                    ("_columns", "product"),
                    ("_columns", "version"),
                    ("_results_number", n),
                ]
                time.sleep(REQUEST_DELAY)
                resp = requests.get(base_url, params=params, timeout=30)

        if resp.status_code == 400:
            print(f"    All attempts failed, skipping. Response: {resp.text[:200]}")
            return []

        if resp.status_code == 429:
            print("    Rate limited, waiting 30s...")
            time.sleep(30)
            resp = requests.get(url, timeout=30)

        resp.raise_for_status()
        data = resp.json()
        return data.get("hits", [])

    except Exception as e:
        print(f"    SuperSearch error: {e}")
        return []


#FETCH PROCESSED CRASH (STACK FRAMES)


def fetch_stack_frames(crash_id):
    """
    Fetch processed crash from Socorro to get crashing thread frames. Returns dict with crash_id, frames, metadata — or None if unavailable.
    """
    url = "https://crash-stats.mozilla.org/api/ProcessedCrash/"
    params = {"crash_id": crash_id}

    try:
        resp = requests.get(url, params=params, timeout=30)

        if resp.status_code == 429:
            print("    Rate limited, waiting 30s...")
            time.sleep(30)
            resp = requests.get(url, params=params, timeout=30)

        if resp.status_code in (403, 404):
            return None

        resp.raise_for_status()
        data = resp.json()

        json_dump = data.get("json_dump", {})
        crash_info = json_dump.get("crash_info", {})
        crashing_thread_idx = crash_info.get("crashing_thread", 0)
        threads = json_dump.get("threads", [])

        if crashing_thread_idx < len(threads):
            raw_frames = threads[crashing_thread_idx].get("frames", [])
            frames = []
            for frame in raw_frames[:15]:
                frames.append({
                    "frame_idx": frame.get("frame", 0),
                    "function": frame.get("function", ""),
                    "module": frame.get("module", ""),
                    "file": frame.get("file", ""),
                    "line": frame.get("line", None),
                })
            return {
                "crash_id": crash_id,
                "frames": frames,
                "os_name": data.get("os_name", ""),
                "product": data.get("product", ""),
                "version": data.get("version", ""),
            }

        return None

    except Exception as e:
        print(f"    ProcessedCrash error for {crash_id}: {e}")
        return None



# MAIN FETCH LOOP


def fetch_all(selected_sigs, sig_to_bugs):
    """
    For each selected signature:
    1. Get crash UUIDs from SuperSearch
    2. Fetch stack frames for each UUID
    3. Write to JSONL as we go (resume-safe)
    """
    already_fetched_sigs = set()
    if os.path.exists(CRASH_REPORTS_FILE):
        with open(CRASH_REPORTS_FILE, "r") as f:
            for line in f:
                if line.strip():
                    record = json.loads(line)
                    already_fetched_sigs.add(record.get("signature", ""))
        print(f"  Resuming: {len(already_fetched_sigs)} signatures already fetched")

    sigs_to_fetch = [s for s in selected_sigs if s not in already_fetched_sigs]
    print(f"  Signatures remaining: {len(sigs_to_fetch)}")

    total_reports = 0
    total_failed = 0

    with open(CRASH_REPORTS_FILE, "a") as f:
        for i, sig in enumerate(sigs_to_fetch):
            bug_ids = list(sig_to_bugs.get(sig, set()))
            print(f"\n[{i+1}/{len(sigs_to_fetch)}] \"{sig[:70]}\"")
            print(f"  Bug(s): {bug_ids}")

            time.sleep(REQUEST_DELAY)
            hits = fetch_crash_ids(sig)
            print(f"  Found {len(hits)} crash reports")

            if not hits:
                record = {
                    "signature": sig,
                    "true_bug_ids": bug_ids,
                    "crash_id": None,
                    "frames": [],
                    "status": "no_reports_found",
                }
                f.write(json.dumps(record) + "\n")
                f.flush()
                continue

            for j, hit in enumerate(hits):
                uuid = hit["uuid"]
                time.sleep(REQUEST_DELAY)
                crash_data = fetch_stack_frames(uuid)

                if crash_data:
                    record = {
                        "signature": sig,
                        "true_bug_ids": bug_ids,
                        "crash_id": crash_data["crash_id"],
                        "frames": crash_data["frames"],
                        "os_name": crash_data.get("os_name", ""),
                        "product": crash_data.get("product", ""),
                        "version": crash_data.get("version", ""),
                        "status": "ok",
                    }
                    f.write(json.dumps(record) + "\n")
                    f.flush()
                    total_reports += 1
                    n_frames = len(crash_data["frames"])
                    print(f"    [{j+1}/{len(hits)}] OK {uuid[:16]}... ({n_frames} frames)")
                else:
                    total_failed += 1
                    print(f"    [{j+1}/{len(hits)}] SKIP {uuid[:16]}... (unavailable)")

    return total_reports, total_failed


#MAin MEthod

if __name__ == "__main__":
    print("="*60)
    print("FETCH STACK TRACES FROM SOCORRO")
    print("="*60)

    print("\nLoading ground truth...")
    gt_rows, sig_to_bugs, bug_to_sigs = load_ground_truth()
    print(f"  Loaded {len(gt_rows)} rows, {len(sig_to_bugs)} unique signatures, {len(bug_to_sigs)} bugs")

    print("\nSelecting signatures to fetch...")
    selected, split_sigs, merge_sigs, clean_sigs = select_signatures(sig_to_bugs, bug_to_sigs)

    est_calls = len(selected) * (1 + REPORTS_PER_SIGNATURE)
    est_minutes = est_calls * REQUEST_DELAY / 60
    print(f"\n  Estimated API calls: ~{est_calls}")
    print(f"  Estimated time: ~{est_minutes:.0f} minutes")
    print(f"  (Script is resume-safe — stop and restart anytime)")

    input("\nPress Enter to start fetching (or Ctrl+C to cancel)...")

    total_ok, total_fail = fetch_all(selected, sig_to_bugs)

    summary = {
        "total_signatures_selected": len(selected),
        "split_sigs": len(split_sigs),
        "merge_sigs": len(merge_sigs),
        "clean_sigs": len(clean_sigs),
        # "priority_sigs": len(PRIORITY_SIGNATURES),
        "reports_fetched": total_ok,
        "reports_failed": total_fail,
    }
    with open(FETCH_SUMMARY_FILE, "w") as f:
        json.dump(summary, f, indent=2)

    print("\n" + "="*60)
    print("="*60)
    print(f"  Reports fetched: {total_ok}")
    print(f"  Reports failed:  {total_fail}")
    print(f"  Files:")
    print(f"    {CRASH_REPORTS_FILE}   <- stack traces (JSONL)")
    print(f"    {FETCH_SUMMARY_FILE}   <- fetch summary")
