# W05 — Canonical Collector → Bronze → Silver contract (proposal for #26, #27, #29)

**Status: COMMON CONTRACT PROPOSAL — NOT YET CROSS-TEAM APPROVED.** 25/10/2026. Data owns Bronze→Silver mapping and storage; Software owns collection and raw Bronze creation; Cyber reviews traceability and missing evidence. This change **does not close** any issue.

## Decision: one event format, one source of truth

**Use existing Software `bronze-event/1.0` as the sole canonical Bronze record**. JSON Schema lives at [poc/sysmon-collector/bronze-event.schema.json](../../../../poc/sysmon-collector/bronze-event.schema.json). This matches the existing `bronze_contract.py` and preserves both original Sysmon `raw_xml` and `event_data` names. It is not the same as a W03 normalized event nor the Data W05 draft that calls the Bronze envelope "v1.1". Both documents are historical proposals until Data and Software sign off on this reconciliation.

**Separation of responsibilities:**

```text
Sysmon XML (input)
  → Software: bronze_contract.build_bronze_record()
  → canonical Bronze JSONL, schema_version bronze-event/1.0
       raw_xml + event_data, time_created + ingest metadata, event_id
  → Data: bronze_to_silver_adapter.to_silver_input()
       timestamp + raw_data + normalized event_type
  → Data: SilverValidatorEngine.process_record(...) [W05 PoC]
       Silver categories; then Feature/Gold contracts (design only)
```

## Common fields and ownership

| Meaning | Bronze 1.0 (canonical) | Silver input (adapted) | Rule |
|---|---|---|---|
| Identity | `event_id` + `hostname/channel/record_id` | Same values | UUIDv5 on original `Computer|Channel|EventRecordID`; log reset still requires epoch design |
| Event kind | `sysmon_event_id` | `sysmon_event_id` and derived `event_type` | Distinguish Sysmon numeric ID from business enum |
| Event source clock | `time_created` | `timestamp` | System.TimeCreated.SystemTime; do not substitute Sysmon EventData.UtcTime |
| Original payload | `raw_xml`, `event_data` | `raw_data` = copy of `event_data` | Never fake fields; original XML stays in Bronze |
| Host | `hostname`, derived `host_id` | `hostname` | host_id is optional downstream metadata, not replacement for hostname |
| Ingest metadata | `ingest.collector`, `collected_at`, `source_file`, `batch_id`, `seq` | `bronze_source` reference (PoC only) | Persistent segment/offset/checksum/ledger remains W06 |
| Entity | EventData.ProcessGuid if present | `process_guid` if present | ID 5 no parent; DNS 22 no socket fields; ID4/16 do not imply ProcessGuid |

**Scope:** one Sysmon event per JSONL line, UTF-8 LF; event payloads are not a list. Bronze is immutable once sealed; segment/manifest/checkpoint writer remains *design only*. Pydantic/DuckDB targets refer to Silver, not a second Bronze envelope.

## Shared synthetic input/output examples

All paths relative to the repository root:

- [Input: synthetic_process_event1.xml](examples/synthetic_process_event1.xml) — **synthetic lab event**, not a real workstation sample.
- [Canonical output: bronze_process_event1.json](examples/bronze_process_event1.json) — expected Bronze 1.0 record, original XML included.
- [Adapter output: silver_input_process_event1.json](examples/silver_input_process_event1.json) — Data validator input, not a claim that this is a persisted Silver row.
- [Reference adapter](../../../../poc/sysmon-collector/bronze_to_silver_adapter.py), [test](../../../../poc/sysmon-collector/test_canonical_bronze_contract.py).

**Reproduce tests from repo root** after installing `pytest` and `jsonschema`:

```powershell
python -m pytest -q poc/sysmon-collector/test_bronze_contract.py poc/sysmon-collector/test_canonical_bronze_contract.py poc/sysmon-collector/test_sysmon_collector_poc.py
```

The new test verifies exact input→Bronze→adapter output, validation, successful ingestion and duplicate replay, and rejects tampered identifiers/raw payload. These are **test cases committed for execution**, not claimed PASS until run in a matching environment.

## What changed and what remains open

**Changed:** fixed schema path in `bronze_contract.py`, fixed synthetic fixture paths in two existing test files, added a reference adapter and synthetic shared examples. No existing W03 JSON files, real samples or architecture reports are overwritten.

**Open before #26 sign-off:** Data/Software formally accept canonical Bronze 1.0 vs prior Data v1.1 draft; decide how to persist `bronze_source` to Silver; implement atomic segment/manifest, checksum, quarantine, bookmark, Windows live mode and replay, and document late/out-of-order behavior. Distinguish schema validation from detection-field insufficiency. The Data `validator_poc.py` currently rejects all Sysmon state events without ProcessGuid; do not silently declare them supported. Also test real Event 5/22/26 and timestamp-skew separately.

## Role sign-off

| Role | Status | Evidence link |
|---|---|---|
| Data (#27) | Pending owner review | — |
| Software (#29) | Pending owner review | — |
| Cyber (#28) | Contract supports raw traceability design, pending joint review | — |
| Team (#26) | Not accepted until Data+Software resolve open questions | — |

**References:** [Team #26](https://github.com/Kientran18/DACN/issues/26), [Data #27](https://github.com/Kientran18/DACN/issues/27), [Software #29](https://github.com/Kientran18/DACN/issues/29), [Cyber W05](../../research/cyber/w5/03-security-review-schema-quality-retention.md).
