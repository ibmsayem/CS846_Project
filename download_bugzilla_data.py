"""
Download crash data from Bugzilla and build ground truth table:
    pip install requests
    python download_bugzilla_data.py
"""

import requests
import json
import csv
import time
import os
from collections import defaultdict

# ── CONFIG ──
OUTPUT_DIR = "data"
JSONL_FILE = os.path.join(OUTPUT_DIR, "bugzilla_crashes.jsonl")
GROUND_TRUTH_FILE = os.path.join(OUTPUT_DIR, "ground_truth.csv")
SUMMARY_FILE = os.path.join(OUTPUT_DIR, "dataset_summary.json")

LIMIT_PER_PAGE = 500       # Bugzilla max per request
MAX_BUGS = 10000            # Total bugs to download (adjust as needed)
REQUEST_DELAY = 1.0        # Seconds between requests (be polite)

os.makedirs(OUTPUT_DIR, exist_ok=True)


def download_bugs():
    """
    Query Bugzilla REST API for bugs with non-empty cf_crash_signature.
    Saves each bug as one line in a JSONL file.
    """
    print("="*60)
    print("DOWNLOADING BUGS FROM BUGZILLA")
    print("="*60)

    url = "https://bugzilla.mozilla.org/rest/bug"
    all_bugs = []
    offset = 0

    with open(JSONL_FILE, "w") as f:
        while offset < MAX_BUGS:
            params = {
                "f1": "cf_crash_signature",
                "o1": "isnotempty",
                "include_fields": "id,summary,cf_crash_signature,product,component,status,resolution",
                "limit": LIMIT_PER_PAGE,
                "offset": offset,
                "order": "bug_id DESC",   # newest first
            }

            print(f"\n  Fetching bugs {offset} to {offset + LIMIT_PER_PAGE}...")
            try:
                resp = requests.get(url, params=params, timeout=60)
                resp.raise_for_status()
                data = resp.json()
            except Exception as e:
                print(f"  ERROR: {e}")
                break

            bugs = data.get("bugs", [])
            if not bugs:
                print("  No more bugs returned. Done.")
                break

            for bug in bugs:
                # Write each bug as one JSON line
                f.write(json.dumps(bug) + "\n")
                all_bugs.append(bug)

            print(f"  Got {len(bugs)} bugs (total so far: {len(all_bugs)})")
            offset += LIMIT_PER_PAGE
            time.sleep(REQUEST_DELAY)

    print(f"\nSaved {len(all_bugs)} bugs -> {JSONL_FILE}")
    return all_bugs


def parse_crash_signatures(raw_field):
    """
    Parse Bugzilla's cf_crash_signature field.
    Format: [@SignatureName] on each line.
    Returns list of clean signature strings.
    """
    if not raw_field:
        return []

    signatures = []
    for line in raw_field.strip().split("\n"):
        line = line.strip()
        if not line:
            continue
        # Remove brackets and @ prefix: "[@PRMJ_Now()]" -> "PRMJ_Now()"
        if line.startswith("[@") and line.endswith("]"):
            sig = line[2:-1].strip()
        elif line.startswith("[") and line.endswith("]"):
            sig = line[1:-1].strip()
        else:
            sig = line
        if sig:
            signatures.append(sig)

    return signatures


def build_ground_truth(bugs):
    """
    Build ground truth table from downloaded bugs.
    Each row: crash_signature -> true_bug_id

    Also identifies split cases and merge cases automatically.
    """
    print("\n" + "="*60)
    print("BUILDING GROUND TRUTH")
    print("="*60)

    # Flat table: signature -> bug_id
    gt_rows = []
    sig_to_bugs = defaultdict(set)     # signature -> set of bug_ids (merge detection)
    bug_to_sigs = defaultdict(list)    # bug_id -> list of signatures (split detection)

    for bug in bugs:
        bug_id = bug["id"]
        summary = bug.get("summary", "")
        raw_sig = bug.get("cf_crash_signature", "")
        signatures = parse_crash_signatures(raw_sig)

        bug_to_sigs[bug_id] = signatures
        for sig in signatures:
            sig_to_bugs[sig].add(bug_id)
            gt_rows.append({
                "crash_signature": sig,
                "true_bug_id": bug_id,
                "bug_summary": summary,
            })

    # Save ground truth CSV
    with open(GROUND_TRUTH_FILE, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["crash_signature", "true_bug_id", "bug_summary"])
        writer.writeheader()
        writer.writerows(gt_rows)
    
    # ── Append our manually verified cases ──
    manual_rows = [
        {"crash_signature": "PRMJ_Now()", "true_bug_id": 817396, "bug_summary": "crash in PRMJ_Now"},
        {"crash_signature": "@0x0 | PRMJ_Now()", "true_bug_id": 817396, "bug_summary": "crash in PRMJ_Now"},
        {"crash_signature": "IncrementalCollectSlice", "true_bug_id": 817396, "bug_summary": "crash in PRMJ_Now"},
        {"crash_signature": "PRMJ_Now", "true_bug_id": 817396, "bug_summary": "crash in PRMJ_Now"},
        {"crash_signature": "@0x0 | PRMJ_Now", "true_bug_id": 817396, "bug_summary": "crash in PRMJ_Now"},
        {"crash_signature": "mozilla::ShouldClearTargets", "true_bug_id": 1462746, "bug_summary": "Crash in mozilla::ShouldClearTargets"},
        {"crash_signature": "static bool mozilla::ShouldClearTargets", "true_bug_id": 1462746, "bug_summary": "Crash in mozilla::ShouldClearTargets"},
        {"crash_signature": "OOM | large | mozalloc_abort | xul.dll | _PR_NativeRunThread | pr_root", "true_bug_id": 1725571, "bug_summary": "Windows 7 x86 OOM crash"},
        {"crash_signature": "OOM | large | mozalloc_abort | mozalloc_handle_oom | gkrust_shared::oom_hook::hook | std::alloc::rust_oom | webrender_bindings::bindings::wr_state_new", "true_bug_id": 1531819, "bug_summary": "OOM crash in webrender"},
        {"crash_signature": "OOM | large | mozalloc_abort | mozalloc_handle_oom | moz_xmalloc | std::basic_string<T>::_Reallocate_grow_by<T>", "true_bug_id": 1626318, "bug_summary": "OOM crash in input handling"},
        {"crash_signature": "OOM | large | mozalloc_abort | moz_xmalloc | mozilla::SPSCRingBufferBase<T>::SPSCRingBufferBase", "true_bug_id": 1757618, "bug_summary": "OOM crash in audio ring buffer"},
    ]

    # Remove duplicates — only append if signature+bug_id pair doesn't already exist
    existing_pairs = {(row["crash_signature"], str(row["true_bug_id"])) for row in gt_rows}
    new_rows = [r for r in manual_rows if (r["crash_signature"], str(r["true_bug_id"])) not in existing_pairs]

    if new_rows:
        with open(GROUND_TRUTH_FILE, "a", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["crash_signature", "true_bug_id", "bug_summary"])
            writer.writerows(new_rows)
        gt_rows.extend(new_rows)
        print(f"  Appended {len(new_rows)} manually verified rows ({len(manual_rows) - len(new_rows)} were already present)")

    print(f"  Total rows: {len(gt_rows)}")
    print(f"  Unique signatures: {len(sig_to_bugs)}")
    print(f"  Unique bugs: {len(bug_to_sigs)}")
    print(f"  Saved -> {GROUND_TRUTH_FILE}")

    # ── Find SPLIT cases: 1 bug -> multiple signatures ──
    split_cases = {bid: sigs for bid, sigs in bug_to_sigs.items() if len(sigs) > 1}

    # ── Find MERGE cases: 1 signature -> multiple bugs ──
    merge_cases = {sig: list(bids) for sig, bids in sig_to_bugs.items() if len(bids) > 1}

    print(f"\n  SPLIT cases (1 bug -> multiple signatures): {len(split_cases)}")
    count = 0
    for bid, sigs in sorted(split_cases.items(), key=lambda x: len(x[1]), reverse=True):
        if count < 10:  # Show top 10
            print(f"    Bug #{bid}: {len(sigs)} signatures")
            for s in sigs[:3]:
                print(f"      -> {s[:80]}")
            if len(sigs) > 3:
                print(f"      ... and {len(sigs)-3} more")
        count += 1

    print(f"\n  MERGE cases (1 signature -> multiple bugs): {len(merge_cases)}")
    count = 0
    for sig, bids in sorted(merge_cases.items(), key=lambda x: len(x[1]), reverse=True):
        if count < 10:
            print(f"    \"{sig[:70]}\"")
            print(f"      -> Bugs: {bids[:5]}{'...' if len(bids)>5 else ''}")
        count += 1

    # ── Save summary ──
    summary = {
        "total_bugs": len(bug_to_sigs),
        "total_signatures": len(sig_to_bugs),
        "total_rows": len(gt_rows),
        "split_cases_count": len(split_cases),
        "merge_cases_count": len(merge_cases),
        "top_split_cases": [
            {"bug_id": bid, "num_signatures": len(sigs), "signatures": sigs[:5]}
            for bid, sigs in sorted(split_cases.items(), key=lambda x: len(x[1]), reverse=True)[:20]
        ],
        "top_merge_cases": [
            {"signature": sig, "num_bugs": len(bids), "bug_ids": bids[:10]}
            for sig, bids in sorted(merge_cases.items(), key=lambda x: len(x[1]), reverse=True)[:20]
        ],
    }
    with open(SUMMARY_FILE, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"\n  Summary saved -> {SUMMARY_FILE}")

    return gt_rows, split_cases, merge_cases


def load_from_jsonl():
    """Load previously downloaded JSONL if it exists."""
    if not os.path.exists(JSONL_FILE):
        return None
    bugs = []
    with open(JSONL_FILE) as f:
        for line in f:
            line = line.strip()
            if line:
                bugs.append(json.loads(line))
    return bugs


if __name__ == "__main__":
    # Check if we already have data
    existing = load_from_jsonl()
    if existing:
        print(f"Found existing {JSONL_FILE} with {len(existing)} bugs.")
        print("Delete it to re-download, or using existing data.\n")
        bugs = existing
    else:
        bugs = download_bugs()

    gt_rows, split_cases, merge_cases = build_ground_truth(bugs)

    print("\n" + "="*60)
    print("STEP 1 COMPLETE")
    print("="*60)
    print(f"  Files created:")
    print(f"    {JSONL_FILE}           <- raw bug data (JSONL)")
    print(f"    {GROUND_TRUTH_FILE}    <- signature-to-bug mapping")
    print(f"    {SUMMARY_FILE}   <- split/merge case summary")
    print(f"\n  Next step: fetch stack traces from Socorro for these signatures.")