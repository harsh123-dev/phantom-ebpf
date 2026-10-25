# PHANTOM Research Audit

**Target:** *PHANTOM: Causal Attribution of Runtime SBOM Drift via eBPF Behavioral Contracts in Kubernetes*  
**Audited source:** `PHANTOM_Research_Paper_Revised (4).pdf`, the editable manuscript in `output/phantom_audit`, repository source, experiment records, and prior audit artifacts available in this workspace.  
**Revised copy:** `PHANTOM_Research_Paper_Final_Source.tex` and compiled PDF in this directory.

## Scope and evidence limits

The earlier ChatGPT conversations are not available for direct review. Earlier decisions were therefore preserved only where they were reflected in the current manuscript or project artifacts. The original PDF and prior source/audit files were not modified. The current paper retains the title, project scope, authors, and guide information already present in the editable source.

The audit compared the manuscript with implementation code and saved artifacts. Unit tests establish that exercised code paths behave under test inputs; they do not establish live detection accuracy, causal correctness, or operational performance.

## Findings and completion checklist

| Severity | Issue and evidence | Status | Change or disposition |
|---|---|---|---|
| High | The evaluation summary's attribution accuracy of 1.0 has no per-run predicted PURL-to-oracle comparison; raw3 events have missing/ambiguous identity and null SBOM/PURL fields. | Corrected using verified evidence | Manuscript says causal/component attribution accuracy is unverified and does not report 100%. |
| High | `research/datasets/raw3/` contains six completed attack runs and three failed SolarWinds-style injections; six positive windows are event-presence observations, not verified component-level detections. | Already resolved — preserved | Preserved the six run counts and latencies while restricting interpretation to event presence. Failed injections are excluded from detection denominators. |
| High | No valid benign controls or numeric true-negative denominator in raw3. The legacy `raw/` collection contains 114 JSON files, including 44 `dry-run-pod` records and no nonempty `phantom_detections` field. | Corrected using verified evidence | Clarified that legacy scenario labels/placeholders do not establish live control observations. FPR, precision, specificity, F1, and false positives/hour remain unavailable. |
| High | PCEPS code exists, but trained model, calibration artifact, scored windows, prospective labels, and supporting performance outputs were not found among the supplied result artifacts. | Already resolved — preserved | Retained the implementation description, removed unsupported predictive-performance claims, and explicitly labels PCEPS results unvalidated/unavailable. |
| High | Causal adapter and temporal projection exist, but supplied attack records lack independent causal ground truth; a semantic tier ordering and constructed treatment/outcome edges are assumptions, not causal proof. | Corrected using verified evidence | Added this limitation and distinguished software abstention tests from causal validation. |
| High | Saved CPU, memory, and event-lag snapshots are all zero without provenance or raw monitoring samples. | Already resolved — preserved | Kept overhead marked unmeasured; no zero-cost claim. |
| Medium | Falco and Trivy baseline setup was skipped; Falco alert outputs are absent; Isolation Forest fit synthetic frequency data. Trivy is a static vulnerability scanner. | Already resolved — preserved | Retained these dry-run facts and withdrew comparative-performance interpretation. |
| Medium | The manuscript had duplicate `Threats to Validity` subsection headings, with a benign-control subsection between them. | Corrected using verified evidence | Reorganized into one proposed benign-control protocol followed by one threats-to-validity section. |
| Medium | Related work did not adequately discuss closest runtime/SBOM integration work and overstated what other runtime tools could answer. | Corrected using verified evidence | Added Bomfather and eBPF/IMA work, softened tool capability language, and marked Table I qualitative/design-level only. |
| Medium | The complete pipeline was spread over implementation descriptions without a concise evidence-gated overview. | Corrected using verified evidence | Added Algorithm 2 using code-supported gates and explicit unavailable statuses; it does not claim end-to-end evaluation or invent an alert threshold. |
| Medium | PCEPS equation omitted implementation clamp endpoints. | Corrected using verified evidence | Documented the implementation's `10^-7` input clamp, fixed 0–100 scaling, and unvalidated calibration/future-outcome meaning. |
| Medium | Original six-page online-compiled PDF had crowded tables and references; the current build uses IEEE two-column layout and added two related-work records. | Corrected using verified evidence | Recompiled a nine-page PDF and visually inspected all pages. Tables and references remain within the page; algorithm 2 is compact but dense. |
| Low | Raw3 manifest lacks kernel, Kubernetes/container versions, experiment commit, full image digests, and Python/DoWhy experiment versions. | Unresolved due to missing implementation or experimental evidence | Missing fields remain explicitly listed in the paper; they require a controlled rerun to fill. |
| Low | Repository URL and Zenodo dataset DOI are not present in checked-in materials. | Unable to verify | Kept the manuscript's placeholder/unavailable statement; did not invent a URL or DOI. |

## Algorithm and implementation consistency

The existing Algorithm 1 for behavioral-contract construction was retained. The new overview is conditional: SBOM verification must succeed; unresolved component identity stays unresolved; a contract comparison is only available when a valid contract exists; DoWhy returns an estimate only after the implemented eligibility checks; PCEPS is unavailable without model/calibration artifacts. No alert threshold, probability calibration, or end-to-end result is implied.

The BDG is described as a typed directed multigraph with decayed evidence weights. The paper explicitly states that graph association and fixed semantic tier ordering do not establish causation. The KL output remains a numeric divergence/novelty score, not a calibrated binary decision.

## Scientific claims retained

The paper reports only the verified run-level values: six completed attack runs, recorded event presence in each, injection-to-first-event mean 15.74 s, median 5.52 s, and linearly interpolated P95 54.72 s. It does not call this a validated attack recall estimate. The three failed injections, missing PURL mappings, absent control denominator, unsupported PCEPS results, and unmeasured overhead remain visible.

The local prior test report records 454 passed and one skipped across the core library and five services. This is reported as software-path testing only, not evidence of security efficacy.

## Output validation

- Original input PDF and earlier project sources remain unchanged.
- The revised source compiled successfully with the desktop LaTeX compiler and local XeLaTeX compiler.
- The final PDF contains nine pages; extracted text confirms one `Threats to Validity` heading, both algorithms, all 30 reference labels, author names, and no TODO marker.
- All nine final rendered pages were visually inspected. The capability table now wraps within the full-width layout; the algorithms and two-column bibliography fit within page bounds.
- No overfull hbox remains in the final LaTeX log. MiKTeX substitutes Latin Modern for unavailable Times font shapes and reports underfull boxes in prose/references; visual inspection shows no clipped content. Consider standardizing on an IEEE-supported font/compiler in the submission build.

## Overall assessment

The revised manuscript is more consistent with the code and current evidence. The core research question remains worthwhile, but component-level causal attribution and PCEPS predictive validity remain unproven. The essential next steps are valid benign controls, per-run component ground truth, resolved image/PURL mapping, repeatable failed-attack scenarios, trained/held-out PCEPS artifacts, and reproducibility/overhead measurements.


