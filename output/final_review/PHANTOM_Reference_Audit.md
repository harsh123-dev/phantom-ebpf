# PHANTOM Reference Audit

This audit checks the 28 references in the supplied editable manuscript plus two records added to cover closest related runtime/SBOM work. Existing references [1] and [4] remain without hyperlinks, preserving the user's prior request to remove those two links. The manuscript's numeric citations [1]–[30] all resolve to bibliography items.

## Reference-level disposition

| Ref. | Manuscript entry | Audit result |
|---:|---|---|
| 1 | CISA XZ Utils alert AA24-089A | Alert identity/date represented as a CISA advisory; URL omitted by prior user request. |
| 2 | A. Freund, xz/liblzma backdoor post, 2024 | Openwall URL is present; original incident/post reference retained. |
| 3 | CISA Alert AA20-352A | URL and December 2020 alert identifier present. |
| 4 | FireEye SUNBURST report, 2020 | Entry retained; URL omitted by prior user request. |
| 5 | Apache Log4j CVE-2021-44228 security information | Official project URL present. |
| 6 | NIST NVD CVE-2021-44228 | Official NVD URL present. |
| 7 | Falco documentation | Project documentation URL; product capability statements are qualified by configuration. |
| 8 | Tetragon documentation | Project URL; capability statements are qualified by deployment and identity integration. |
| 9 | Tracee project | Project URL; text distinguishes event collection from causal estimation. |
| 10 | CycloneDX specification | Specification archive URL; version 1.4 citation retained as a dated source. |
| 11 | NTIA minimum SBOM elements | Official NTIA URL present. |
| 12 | Anchore Enterprise product page | Vendor URL; treated as product capability context, not independent performance evidence. |
| 13 | Ox Security product page | Vendor URL; treated as product capability context, not independent performance evidence. |
| 14 | Chen et al., cloud incident RCA, EuroSys 2024 | Venue/year/pages retained from existing manuscript; verify exact author list/title against proceedings metadata before submission. |
| 15 | Pearl, *Causality*, 2nd ed. | Standard book citation, 2009. |
| 16 | Sharma and Kiciman, DoWhy, arXiv:2011.04216 | arXiv identifier and URL present. |
| 17 | Google Online Boutique | Official GitHub project URL; cited as a possible future workload, not a completed experiment. |
| 18 | DARPA Transparent Computing materials | Program URL; used only for context on system evidence/provenance. |
| 19 | KubeArmor project documentation | Project URL; table describes policy capabilities qualitatively. |
| 20 | Anchore Syft | Official project URL; cited as SBOM generation tooling. |
| 21 | Sigstore Cosign | Official documentation URL; cited for verification interfaces. |
| 22 | eBPF Foundation eBPF overview | Official project documentation URL. |
| 23 | Hagberg, Schult, and Swart, NetworkX, SciPy 2008 | Bibliographic entry retained; confirm proceedings pagination/source metadata during final venue-specific reference cleanup. |
| 24 | Chen and Guestrin, XGBoost, KDD 2016 | Bibliographic entry retained for the named model implementation. |
| 25 | Platt, probabilistic outputs, 1999 | Bibliographic entry retained for the calibration mapping concept; the paper does not claim calibration success. |
| 26 | Package URL specification | Project specification URL present. |
| 27 | Cosign container-signing documentation | Official documentation URL present. |
| 28 | libbpf CO-RE reference | Official project URL present. |
| 29 | Srinivasan, Naveen, and Naveen, Bomfather, arXiv:2503.02097 (2025) | Official arXiv record used. The text distinguishes Bomfather's build-time eBPF dependency observation/SBOM scope from PHANTOM's post-deployment research question. This remains an arXiv preprint, not peer-reviewed evidence. |
| 30 | Crawford, Yakubovich, and Szumski, eBPF and IMA SBOM enforcement, SCORED 2023, pp. 77–78, DOI 10.1145/3605770.3625206 | DOI/proceedings metadata retained; cited to establish prior SBOM/kernel integration. |

## Comparison corrections

The previous categorical statement that Falco, Tetragon, and Tracee cannot answer package-level questions was narrowed. The revised text says package attribution depends on runtime configuration and identity-mapping integrations, and that event collection or policy enforcement alone is not a causal estimate. Table I is expressly qualitative and not a performance benchmark. Bomfather and eBPF/IMA work are now represented in the related-work narrative and capability table.

## Remaining manual checks

Before formal submission, verify the exact author list and title capitalization for [14], full proceedings metadata for [23], and the exact version/date of vendor/project web pages [7]–[13], [17]–[22], [26]–[28]. The current audit confirms the cited records/URLs and the manuscript's limited use of those sources, but does not claim a complete independent archival metadata check of every web document. Avoid describing vendor feature pages as comparative performance evidence.
