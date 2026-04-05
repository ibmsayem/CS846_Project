"""

Fetches FULL processed crash reports (same structure as Socorro's ProcessedCrash API) and maps each to its Bugzilla bug ID.

"""

import os
import time
import json
import logging
import requests
import pandas as pd
from pathlib import Path
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock


BASE_URL    = "https://crash-stats.mozilla.org/api"
API_TOKEN   = os.environ.get("CRASHSTATS_API_TOKEN", "")

PRODUCT     = "Firefox"
DATE_FROM   = ">=2026-03-10" # adjustable
DATE_TO     = "<2026-03-17" # adjustable
MAX_CRASHES = 10000       # Total full crash reports to fetch
BATCH_SIZE  = 100          # SuperSearch page size (max 100)
# WORKERS     = 10           # Parallel threads for ProcessedCrash API calls
#                            # Increase to 20 if you have a token; keep at 5 without one
DELAY_SEC   = 0.2          # Per-thread delay between calls to avoid page limit hitting rate limits 
OUTPUT_DIR  = Path(".")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger(__name__)

write_lock = Lock()   # protect file writes across threads



def make_session():
    s = requests.Session()
    s.headers.update({
        "User-Agent": "ground-truth-mapper/1.0 (research)",
        **({"Auth-Token": API_TOKEN} if API_TOKEN else {}),
    })
    return s

"""Fetch up to MAX_CRASHES crash IDs + signatures via SuperSearch."""
def get_crash_ids(session):

    log.info("Collecting crash IDs via SuperSearch …")
    records = []
    offset  = 0

    while len(records) < MAX_CRASHES:
        batch = min(BATCH_SIZE, MAX_CRASHES - len(records))
        params = {
            "product"         : PRODUCT,
            "date"            : [DATE_FROM, DATE_TO],
            "_columns"        : ["uuid", "signature"],
            "_results_number" : batch,
            "_results_offset" : offset,
            "_sort"           : "-date",
        }
        resp = session.get(f"{BASE_URL}/SuperSearch/", params=params, timeout=30)
        resp.raise_for_status()
        data = resp.json()

        hits = data.get("hits", [])
        if not hits:
            break

        for h in hits:
            if h.get("uuid") and h.get("signature"):
                records.append({"crash_id": h["uuid"], "signature": h["signature"]})

        total = data.get("total", 0)
        log.info("  Collected %d / %d  (server total: %d)", len(records), MAX_CRASHES, total)

        if offset + batch >= total:
            break
        offset += batch
        time.sleep(0.2)

    log.info("  → %d crash IDs ready.", len(records))
    return records


def fetch_one(crash_id, session):
    """Fetch a single full processed crash. Returns dict or None."""
    try:
        resp = session.get(
            f"{BASE_URL}/ProcessedCrash/",
            params={"crash_id": crash_id},
            timeout=60,
        )
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        data = resp.json()
        processed = data.get("processed_crash", data)
        processed["crash_id"] = crash_id
        return processed
    except Exception as e:
        log.warning("  FAIL %s: %s", crash_id, e)
        return None


"""Map signatures → Bugzilla bug IDs."""
def get_bug_associations(session, signatures, chunk_size=20):

    log.info("Fetching bug associations for %d unique signatures …", len(signatures))
    sig_to_bugs = {}

    for i in range(0, len(signatures), chunk_size):
        chunk = signatures[i: i + chunk_size]
        try:
            resp = session.get(
                f"{BASE_URL}/Bugs/",
                params=[("signatures", s) for s in chunk],
                timeout=30,
            )
            if resp.ok:
                result = defaultdict(list)
                for hit in resp.json().get("hits", []):
                    result[hit["signature"]].append(hit["id"])
                sig_to_bugs.update(result)
        except Exception as e:
            log.warning("  Bugs API error on chunk %d: %s", i, e)
        time.sleep(0.2)

    matched = sum(1 for v in sig_to_bugs.values() if v)
    log.info("  → %d / %d signatures have a linked bug.", matched, len(signatures))
    return sig_to_bugs



def fetch_all_parallel(id_records, output_jsonl_path):
    """
    Fetch full processed crashes in parallel.
    Writes each result immediately to the JSONL file (streaming).
    Returns list of all successfully fetched crashes.
    """
    log.info("Fetching %d full crash reports (%d parallel workers) …",
             len(id_records), WORKERS)

    full_crashes = []
    done_count   = [0]   # mutable counter for threads
    failed_count = [0]

    # Open the output file for streaming writes
    out_file = open(output_jsonl_path, "w", encoding="utf-8")

    def worker(rec):
        session = make_session()   # each thread gets its own session
        crash   = fetch_one(rec["crash_id"], session)
        time.sleep(DELAY_SEC)
        return crash

    with ThreadPoolExecutor(max_workers=WORKERS) as executor:
        futures = {executor.submit(worker, rec): rec for rec in id_records}

        for future in as_completed(futures):
            rec   = futures[future]
            crash = future.result()

            with write_lock:
                done_count[0] += 1
                if crash:
                    full_crashes.append(crash)
                    out_file.write(json.dumps(crash, default=str) + "\n")
                    out_file.flush()
                else:
                    failed_count[0] += 1

                # Progress every 500
                if done_count[0] % 500 == 0 or done_count[0] == len(id_records):
                    log.info("  Progress: %d / %d  (ok=%d  fail=%d)",
                             done_count[0], len(id_records),
                             len(full_crashes), failed_count[0])

    out_file.close()
    log.info("  → %d crash reports saved, %d failed.", len(full_crashes), failed_count[0])
    return full_crashes


def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    session = make_session()

    # Collect crash IDs
    id_records = get_crash_ids(session)
    if not id_records:
        log.error("No crash IDs found. Check dates / product / network.")
        return

    # Fetch full crash reports in parallel (streaming to JSONL)
    crash_jsonl_path = OUTPUT_DIR / "crash_reports.jsonl"
    full_crashes     = fetch_all_parallel(id_records, crash_jsonl_path)

    #Fetch bug associations
    unique_sigs = list({c.get("signature", "") for c in full_crashes if c.get("signature")})
    sig_to_bugs = get_bug_associations(session, unique_sigs)

    # Write bug_associations.jsonl
    sig_to_crash_ids = defaultdict(list)
    for c in full_crashes:
        sig_to_crash_ids[c.get("signature", "")].append(c["crash_id"])

    bug_records = []
    for sig, bugs in sig_to_bugs.items():
        for bug_id in bugs:
            bug_records.append({
                "bug_id"     : bug_id,
                "signature"  : sig,
                "crash_ids"  : sig_to_crash_ids.get(sig, []),
                "crash_count": len(sig_to_crash_ids.get(sig, [])),
            })

    with open(OUTPUT_DIR / "bug_associations.jsonl", "w", encoding="utf-8") as f:
        for r in bug_records:
            f.write(json.dumps(r, default=str) + "\n")
    log.info("Saved → bug_associations.jsonl  (%d lines)", len(bug_records))

    #Write ground_truth_full.csv  (crash_id | bug_id | signature)
    rows = []
    for c in full_crashes:
        sig  = c.get("signature", "")
        for bug_id in sig_to_bugs.get(sig, []):
            rows.append({
                "crash_id" : c["crash_id"],
                "bug_id"   : bug_id,
                "signature": sig,
            })

    gt_df = pd.DataFrame(rows)
    gt_df.to_csv(OUTPUT_DIR / "ground_truth_full.csv", index=False)
    log.info("Saved → ground_truth_full.csv  (%d rows)", len(gt_df))

    # Summary
    log.info("Summary is given below")
    log.info("  crash_reports.jsonl    → %d full crash reports", len(full_crashes))
    log.info("  bug_associations.jsonl → %d bug-signature pairs", len(bug_records))
    log.info("  ground_truth_full.csv  → %d matched rows (crash × bug)", len(gt_df))
    log.info("  Unique bugs            → %d", gt_df["bug_id"].nunique() if not gt_df.empty else 0)
    log.info("  Unique signatures      → %d", gt_df["signature"].nunique() if not gt_df.empty else 0)


if __name__ == "__main__":
    main()



"""
Outputs generated:
  crash_reports.jsonl: one full processed crash per line
  bug_associations.jsonl: one bug-signature association per line
  ground_truth_full.csv: flat mapping: crash_id | bug_id | signature

"""
