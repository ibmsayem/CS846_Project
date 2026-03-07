# Clustering Error Detection Algorithms



## Algorithm 1: Over-Clustering Detection

> Detects clusters that **incorrectly merge** distinct bugs together.

```
ALGORITHM OverClusteringDetection(clusters, traces, sim_func)
────────────────────────────────────────────────────────────────
INPUT:
    clusters    : list of clusters, each cluster is a list of report IDs
    traces      : map of report ID → stack trace
    sim_func    : function(trace_a, trace_b) → similarity score in [-1, +1]

OUTPUT:
    merge_errors    : clusters that are hiding more than one bug
    aliased_sigs    : signatures that cover unrelated root causes

CONSTANTS:
    SPLIT_THRESHOLD    = 0.10   (if cross-group similarity is below this, two bugs exist)
    ALIAS_THRESHOLD    = 0.15   (if rep similarity is below this, signature is aliased)
    MIN_CLUSTER_SIZE   = 3      (skip clusters smaller than this)


Phase 1: Merge Error Detection


merge_errors ← []

FOR EACH cluster C where |C| >= MIN_CLUSTER_SIZE:

    // Step 1: Score every pair of reports inside the cluster
    FOR every pair (i, j) inside C:
        sim_matrix[i, j] ← sim_func(traces[i], traces[j])

    // Step 2: Pick the two most dissimilar reports as seeds
    (seed_1, seed_2) ← pair with the lowest sim_matrix score

    // Step 3: Assign every other report to its nearest seed
    group_A ← { seed_1 }
    group_B ← { seed_2 }

    FOR EACH remaining report k in C:
        IF sim_func(traces[k], traces[seed_1])
                >= sim_func(traces[k], traces[seed_2]):
            add k to group_A
        ELSE:
            add k to group_B

    // Step 4: Measure average similarity across the two groups
    cross_sim ← average of sim_matrix[a, b]
                for all a in group_A and b in group_B

    // Step 5: Flag the cluster if the two groups are genuinely different
    IF cross_sim < SPLIT_THRESHOLD:
        dominant ← the larger group   (primary bug)
        hidden   ← the smaller group  (bug that was buried)
        ADD to merge_errors:
            { cluster: C, dominant: dominant,
              hidden: hidden, cross_sim: cross_sim }


Phase 2: Signature Aliasing Detection


aliased_sigs ← []

// Group all clusters by their signature label
sig_groups ← GROUP clusters BY signature

FOR EACH signature S that covers >= 2 clusters:

    // Take one representative trace per cluster
    reps ← [ traces[first report of C] for each cluster C under S ]

    // Step 1: Compare every pair of representatives
    low_pairs ← []
    FOR every pair (i, j) in reps:
        sim ← sim_func(reps[i], reps[j])
        IF sim < ALIAS_THRESHOLD:
            ADD (i, j, sim) to low_pairs

    // Step 2: Flag the signature if any pair is too dissimilar
    IF low_pairs is not empty:
        ADD to aliased_sigs:
            { signature: S, num_clusters: count, low_pairs: low_pairs }

RETURN merge_errors, aliased_sigs
```

---


