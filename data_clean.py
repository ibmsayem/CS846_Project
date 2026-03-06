# This file is for cleaning and preprocessing the crash data downloaded from Socorro.
# It reads the raw JSONL file, extracts relevant fields, and outputs a cleaned CSV file for analysis.

import numpy as np
# import pandas as pd
import re
import json




records = []

with open('test.jsonl', 'r') as f:
    for lineno, line in enumerate(f, 1):
        line  = line.strip()
        if not line:
            continue  # Skip empty lines
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError as e:
            print(f"Error decoding JSON on line {lineno}: {e}")

print(f"Total records read: {len(records)}")

