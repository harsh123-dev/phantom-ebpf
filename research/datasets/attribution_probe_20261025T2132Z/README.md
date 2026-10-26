# Harmless live attribution probe

Controller: `/root/phantom-ebpf`; AWS account `253490771520`, region `ap-south-1`, lab instance `i-06bb29d253668fa5f`. This directory contains SSM command responses and the agent source archives used for two diagnostic/race-correction rollouts. No attack scenario was run.

`event_db_record.json` captures a `runc:[2:INIT]` kernel event whose later `/proc/<pid>/exe` lookup yielded `/usr/local/bin/python3.11`, proving that the late lookup could mislabel the event. `racefix_rollout.json` records the corrected agent deployment. `racefix_pipeline.json` records harmless event `f344d15a-5260-478c-9025-022ebe955f56`, its API/Redis outbox progress, and causal acknowledgement. The corrected event leaves executable path/hash and component binding unresolved. `source_fetch_failed.json` records an initial failed host-side source retrieval; it caused no successful rollout.

`SHA256SUMS` hashes each other file in this directory. These are engineering smoke checks, not research-pilot observations or independent ground truth.
