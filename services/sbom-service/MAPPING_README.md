# PHANTOM Part 3 — Runtime-to-SBOM Component Mapping and BDG Validation

## Overview

Part 3 implements and validates the **evidence-based runtime-to-SBOM component
mapping resolver**: the missing link between observed eBPF runtime events and
the software component identities in the Behavioral Dependency Graph (BDG).

**Parts 1 and 2 context:**
- Part 1: Reproducible experimental evaluation pipeline, metrics calculation
- Part 2: Variable-order Markov behavioral drift detector, BIC model selection,
  KL-divergence scoring

**Part 3 scope** (this document):
- Evidence-based mapping resolver (`sbom-service/app/domain/mapping/`)
- Mapping quality metrics with ground-truth evaluation
- 15 SYNTHETIC ground-truth fixture cases
- 84 passing unit tests covering all 5 mapping statuses and all edge cases

---

## Problem Statement

The `BehavioralDependencyGraph.update()` API accepts `binding_status` and
`component_purl` as caller-supplied strings. Before Part 3, **nothing in the
codebase computed these values**. Every event reached the BDG with either an
empty PURL or an assumed-resolved binding, making PURL nodes in the graph
non-evidential — they did not represent real runtime-to-component attribution.

---

## New Files

| File | Purpose |
|------|---------|
| `sbom-service/app/domain/mapping/evidence.py` | Domain value objects: `EvidenceKind`, `EvidenceSource`, `ProcessIdentity`, `ContainerIdentity`, `RuntimeEventRecord` |
| `sbom-service/app/domain/mapping/resolver.py` | `RuntimeToSbomMapper`, `SbomIndex`, `MappingResult`, `MappingStatus` |
| `sbom-service/app/domain/mapping/metrics.py` | `MappingQualityMetrics`, `MappingQualityReport` |
| `sbom-service/app/domain/mapping/__init__.py` | Public package exports |
| `sbom-service/tests/fixtures/mapping_fixtures.py` | 15 SYNTHETIC ground-truth fixture cases (F01–F15) |
| `sbom-service/tests/test_runtime_mapper.py` | 84 unit tests |

---

## Architecture

```
RuntimeEventRecord ──► RuntimeToSbomMapper ──► MappingResult
                              │
                              ▼
                    SbomIndex (pre-built from Sbom + Component + file_inventory)
                              │
                        Evidence tiers (in priority order):
                          A. PURL_DIRECT (not yet active in eBPF collector)
                          B. EXECUTABLE_HASH (not yet active)
                          C. EXECUTABLE_PATH in file inventory  ← active
                          D. FILE_INVENTORY path lookup          ← active
                          E. HEURISTIC_PATH_PREFIX (depth ≥ 5)  ← active
```

---

## Mapping Status Values

| Status | Meaning | BDG BindingStatus |
|--------|---------|-------------------|
| `VERIFIED` | Exact hash or direct PURL evidence | `RESOLVED` |
| `INFERRED` | Path in file inventory, single match | `RESOLVED` |
| `AMBIGUOUS` | Multiple components consistent with evidence | `AMBIGUOUS` |
| `UNRESOLVED` | No SBOM, no image digest, or no evidence match | `MISSING` |
| `INVALID` | Structural validation failure (empty container_id) | `MISSING` |

---

## Ten Mapping Rules Implemented

1. **Verify SBOM/image association** — image digest is mandatory for SBOM lookup.
2. **Resolve to process/container/workload** — container_id and image_digest
   are required; pod_uid is optional.
3. **Only resolve with defensible evidence** — file inventory or hash match.
4. **Exact hashes preferred** — EXECUTABLE_HASH tier (reserved for when the
   eBPF collector gains hash support).
5. **File inventory when available** — EXECUTABLE_PATH and FILE_INVENTORY tiers.
6. **Do NOT infer every package caused every event** — image digest alone
   never produces a PURL candidate.
7. **Interpreter paths do not identify packages** — `/usr/bin/python3` is
   detected by basename, not substring; it is never used as a component
   evidence source. The check operates on the **basename** of the executable,
   so library files like `requests/__init__.py` (which contain "python" in
   their directory path) are NOT misclassified.
8. **Record ambiguity explicitly** — `AMBIGUOUS` status with all candidates.
9. **Preserve UNRESOLVED** — never fabricate a PURL.
10. **Record all evidence** — `MappingResult.evidence` list contains every
    tier's contribution with a human-readable description.

---

## Key Design Decisions

### `is_interpreter` uses basename matching
The previous substring approach (`"python" in full_path`) incorrectly
classified library files under `/usr/lib/python3.11/site-packages/` as
interpreter processes. The fix checks the basename of the executable:

```python
basename = executable_path.rstrip("/").split("/")[-1].lower()
return any(basename.startswith(pattern) for pattern in ("python", "java", ...))
```

### Prefix index minimum depth = 5
The `SbomIndex` prefix index is built at path depths ≥ 5 only. At depth < 5,
common prefixes like `/usr`, `/usr/lib`, or even the empty string (`''`) match
virtually every Linux file path, generating spurious candidates for unrelated
events. Depth 5 corresponds to paths like
`/usr/lib/python3.11/site-packages` — meaningful package directories.

### Interpreter binary excluded from FILE_INVENTORY tier
When `resource_path == executable_path` and the process is an interpreter,
the FILE_INVENTORY tier is skipped. This prevents the interpreter binary itself
from being used as a file-based component attribution clue.

### Metrics require ground truth
`MappingQualityMetrics.compute()` explicitly refuses to report precision/recall
without a `ground_truth` dict. The `notes` field carries an explanation. This
prevents fabricated accuracy numbers in evaluation reports.

---

## Ground-Truth Fixture Cases (SYNTHETIC)

All 15 fixtures are clearly labelled SYNTHETIC. No real experimental results
or real component identities are used.

| Fixture | Scenario | Expected Status |
|---------|----------|-----------------|
| F01 | File path in inventory → single component | `INFERRED` |
| F02 | Container known, path not in inventory | `UNRESOLVED` |
| F03 | PURL in SBOM but event is unrelated | `UNRESOLVED` |
| F04 | Two packages share path prefix | `AMBIGUOUS` |
| F05 | Hash present but hash tier not yet active | `UNRESOLVED` |
| F06 | Library path in inventory, interpreter exec | `INFERRED` |
| F07 | image_digest is None | `UNRESOLVED` |
| F08 | SBOM not indexed for image | `UNRESOLVED` |
| F09 | container_id is empty | `INVALID` |
| F10 | Same PID reused across process lifetimes | Two independent `INFERRED` |
| F11 | Same event_id delivered twice | Two identical `INFERRED` results |
| F12 | Same process, different resource paths | Two separate `INFERRED` |
| F13 | Events arrive out of timestamp order | Both `INFERRED` (stateless) |
| F14 | Container known, pod_uid is None | `INFERRED` |
| F15 | Component in SBOM, no event touches it | `UNRESOLVED` |

---

## Test Results

```
84 passed in 0.40s
```

All tests are synchronous pure-domain unit tests. No database, no HTTP,
no async fixtures needed.

---

## Discrepancies Found and Resolved

| Ref | Discrepancy | Fix |
|-----|------------|-----|
| D-1 | No mapping resolver existed | Implemented `RuntimeToSbomMapper` |
| D-2 | Component.binding_status always AMBIGUOUS at ingest | Resolver produces explicit `MappingResult`; status set only with evidence |
| D-3 | `is_interpreter` matched on full path substring | Changed to basename-only matching |
| D-4 | Prefix index included depth 1–3 (too shallow) | Raised minimum depth to 5 |
| D-5 | Interpreter binary matched FILE_INVENTORY tier | Skip FILE_INVENTORY when resource_path == interpreter executable |
| D-6 | No ground-truth mapping fixtures existed | Created 15 SYNTHETIC fixtures (F01–F15) |

---

## Known Limitations (Preserved, Not Fabricated)

- **Hash tier not yet active**: The eBPF collector does not yet produce
  `executable_hash`. The `EXECUTABLE_HASH` evidence kind is wired but produces
  no candidates. All current mappings are `INFERRED` at best. When the
  collector gains hash support, the tier activates automatically.
- **In-memory idempotency only**: The BDG's `_idempotency_index` is cleared
  on service restart. Distributed deduplication requires a persistent store
  (out of scope for Part 3).
- **File inventory is optional**: The `SbomIndex` only has file-level
  resolution when a Syft JSON with file inventory is provided. Without it,
  the file and prefix tiers produce no candidates.
