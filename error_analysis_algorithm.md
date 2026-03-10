# Clustering Error Detection Algorithms

## Algorithm 1: Over-Clustering Detection

> Detects clusters that **incorrectly merge** distinct bugs together.

```
ALGORITHM OverClusteringDetection(clusters, traces, sim_func)

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

## Algorithm 2: Under-Clustering Detection

> Detects bugs that are **incorrectly split** across multiple clusters.

```
ALGORITHM UnderClusteringDetection(clusters, traces, sim_func)

INPUT:
    clusters : list of clusters, each cluster is a list of report IDs
    traces     : map of report ID → stack trace
    sim_func   : function(trace_a, trace_b) → similarity score in [-1, +1]

OUTPUT:
    cross_sig_dupes : cluster pairs from different signatures that are the same bug
    mis_bucketed    : individual reports sitting in the wrong cluster
    fragments       : tiny clusters that are pieces of a larger bug

CONSTANTS:
    CROSS_THRESHOLD     = 0.35  (if cross-sign similarity is above this, same bug)
    REBUCKET_THRESHOLD  = 0.30  (report only moved if alternative clears this floor)
    FRAGMENT_THRESHOLD  = 0.20  (tiny cluster is a fragment if it clears this)
    TINY_MAX_SIZE       = 2     (clusters this size or smaller are fragment candidates)
    LARGE_MIN_SIZE      = 3     (clusters this size or larger are established bugs)


Phase 1: Same Bug Across Different Signatures


cross_sig_dupes ← []

// Take one representative trace per cluster
reps ← [ (cluster_id, traces[first report], signature) for each cluster ]

FOR EACH pair of clusters (A, B) that have DIFFERENT signatures:
    sim ← sim_func(reps[A].trace, reps[B].trace)
    IF sim >= CROSS_THRESHOLD:
        ADD to cross_sig_dupes:
            { cluster_a: A, cluster_b: B, similarity: sim }


Phase 2: Mis-Bucketed Report Detection


mis_bucketed ← []

// Build a representative trace lookup for all clusters
rep_map ← { cluster_id: traces[first report] for each cluster }

FOR EACH cluster C:
    FOR EACH non-representative report m in C:

        // Step 1 : Score how well m fits its current cluster
        own_sim ← sim_func(traces[m], rep_map[C])

        // Step 2 : Find the best-fitting alternative cluster
        best_other_sim ← -1
        best_other_id  ← null
        FOR EACH other cluster D (where D != C):
            s ← sim_func(traces[m], rep_map[D])
            IF s > best_other_sim:
                best_other_sim ← s
                best_other_id  ← D

        // Step 3 — Flag if report fits better elsewhere AND clears the floor
        IF best_other_sim > own_sim
                AND best_other_sim >= REBUCKET_THRESHOLD:
            ADD to mis_bucketed:
                { report: m, current_cluster: C,
                  better_cluster: best_other_id,
                  own_sim: own_sim, better_sim: best_other_sim }


Phase 3: Fragment Cluster Detection


fragments      ← []
genuine_unique ← 0

// Separate clusters into two size classes
tiny_clusters  ← [ C in clusters where |C| <= TINY_MAX_SIZE  ]
large_clusters ← [ C in clusters where |C| >= LARGE_MIN_SIZE ]

large_reps ← [ (cluster_id, traces[first report]) for each large cluster ]

FOR EACH tiny cluster T:
    rep_T ← traces[first report of T]

    // Step 1: Find the closest large cluster
    best_sim   ← -1
    best_large ← null
    FOR EACH (large_id, large_trace) in large_reps:
        s ← sim_func(rep_T, large_trace)
        IF s > best_sim:
            best_sim   ← s
            best_large ← large_id

    // Step 2 : Classify the tiny cluster
    IF best_sim >= FRAGMENT_THRESHOLD:
        ADD to fragments:
            { tiny_cluster: T, belongs_to: best_large, similarity: best_sim }
    ELSE:
        genuine_unique ← genuine_unique + 1   // rare but real standalone bug

RETURN cross_sig_dupes, mis_bucketed, fragments
```

---