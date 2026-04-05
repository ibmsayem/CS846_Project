"""
Generate ground_truth_deduped.csv from existing ground_truth_full.csv
Reads : ground_truth_full.csv  (uuid | signature | bug_id)
Writes: ground_truth_deduped.csv (signature | bug_ids | bug_count | crash_count)
"""

import pandas as pd
from pathlib import Path

INPUT_CSV  = "ground_truth_full.csv"
OUTPUT_DIR = Path(".")

# Loading the full ground truth CSV
df = pd.read_csv(INPUT_CSV)
print(f"Loaded {len(df)} rows") 
print(f"Unique signatures : {df['signature'].nunique()}")
print(f"Unique bug IDs    : {df['bug_id'].nunique()}")
print(f"Unique crashes    : {df['uuid'].nunique()}")

# ── Deduplicate: group by signature ───────────
dedup_rows = []
for sig, group in df.groupby("signature"):
    bug_ids     = sorted(group["bug_id"].unique().tolist())
    crash_count = group["uuid"].nunique()
    dedup_rows.append({
        "signature"  : sig,
        "bug_ids"    : ",".join(str(b) for b in bug_ids),
        "bug_count"  : len(bug_ids),
        "crash_count": crash_count,
    })

dedup_df = pd.DataFrame(dedup_rows).sort_values("crash_count", ascending=False)
dedup_df.to_csv(OUTPUT_DIR / "ground_truth_deduped.csv", index=False)
print(f"\nSaved → ground_truth_deduped.csv  ({len(dedup_df)} rows)")
