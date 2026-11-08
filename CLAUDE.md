# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repo is

DACN is an academic endpoint-security (EPP/EDR) project for Windows 10/11, written mostly in Vietnamese. The code is a **PoC pipeline, not a product**: there is no running agent, no UI, and no response engine yet. Only the Sysmon collector, a Bronze→Silver validator, and their tests exist. Docs under `docs/` are the bulk of the repo and are the source of the field mappings the code implements.

The live Windows Event Log path (`--mode live`, `pywin32`) has **never been run on a real Windows host**. Everything else is tested against synthetic or lab-captured XML/JSON samples.

## Commands

There is no build system, linter, or root dependency file. Dependencies are installed by hand.

```bash
# Install test deps (pytest/jsonschema are needed for poc/; duckdb is optional for validator_poc.py)
pip install pytest jsonschema duckdb

# Collector PoC suite (pytest-style, 4 files)
python -m pytest -q poc/sysmon-collector

# Validator suite under tests/ (unittest-style classes; pytest also collects them)
python -m pytest -q tests/
python -m unittest tests.test_validator_poc_w5

# Run one test
python -m pytest -q poc/sysmon-collector/test_bronze_contract.py::test_collector_errors_use_reason_codes
python -m unittest tests.test_validator_poc_w5.TestDataPipelineW05.test_01_deterministic_uuidv5_matches_w3_real_samples

# Collector CLI (file mode works on any OS; live mode needs Windows + pywin32 + Administrator)
python poc/sysmon-collector/sysmon_collector_poc.py --mode file \
  --input references/samples/raw/raw_process_create_event1.xml --output /tmp/out.json

# Field-coverage report over the samples
python poc/sysmon-collector/contract_check.py --samples references/samples --out coverage_report.md

# Validator demo (reads references/samples/*.json, prints a Silver/Quarantine summary)
python src/pipeline/validator_poc.py
```

Known failing tests at the time this file was written (they are real failures, not environment issues):
- `tests/test_validator_poc_w5.py::...test_06_time_skew_warning_and_shannon_entropy`: asserts entropy > 5.0 for an encoded command line; the computed value is 4.73.
- `poc/sysmon-collector/test_bronze_contract.py::test_collector_errors_use_reason_codes`: expects a `C-002` message when `TimeCreated` is missing, but `sysmon_collector_poc._parse_event_element` raises `Event XML is missing EventID or TimeCreated` without the code.

Current status: 25 pass / 1 fail in `poc/sysmon-collector`; 5 pass / 1 fail in `tests/`.

## Import model (read before adding modules)

The Python files are not a package. They import each other by bare module name:
- `bronze_contract.py` does `import sysmon_collector_poc as poc`; `bronze_to_silver_adapter.py` imports `bronze_contract` and `sysmon_collector_poc`.
- `test_canonical_bronze_contract.py` imports `bronze_contract`, `bronze_to_silver_adapter`, and `validator_poc` by bare name.
- `tests/test_validator_poc_w5.py` and `test_canonical_bronze_contract.py` insert `src/pipeline` into `sys.path` by hand.

Run the tests from the repo root with `python -m pytest` so pytest's rootdir handling puts `poc/sysmon-collector` on the path. Running a script from another directory will break these imports.

## Architecture: the big picture

The data flows through four stages. Each stage keeps the original Sysmon payload, and none of them invents fields that are absent from the source.

1. **Collect** (`poc/sysmon-collector/sysmon_collector_poc.py`). Parses `<Event>` XML (from `wevtutil`/`Get-WinEvent` exports or live `win32evtlog`) and produces a normalized PoC record. It sets:
   - `event_id` = UUIDv5 over `Computer|Channel|EventRecordID`, using a fixed namespace.
   - `event_type` from a Sysmon-ID mapping, e.g. `1 → PROCESS_START`, `3 → NETWORK_CONNECT/ACCEPT`.
   - `data` (typed fields such as `pid`, `image_path`, `hashes`) and `raw_data` (original EventData names).

2. **Bronze envelope** (`bronze_contract.py` + `bronze-event.schema.json`). Wraps one event in the canonical `bronze-event/1.0` record. The record keeps `raw_xml` and `event_data` verbatim, plus `host_id` (UUIDv5 of the lowercased hostname) and `ingest` metadata. `validate_record` checks the record against the JSON Schema. The schema is the contract that `docs/architecture/w5/contracts/README.md` proposes as the single source of truth. That proposal is **not yet cross-team approved**.

3. **Adapter** (`bronze_to_silver_adapter.py`). `to_silver_input` fails closed. It validates the envelope, recomputes the identity (`event_id`, `host_id`), and checks that the parsed `raw_xml` still matches the stored `event_data`. Any mismatch raises `BRONZE_IDENTITY_MISMATCH` or `BRONZE_RAW_MISMATCH`. It then emits the flat dict that the validator expects.

4. **Validate and route** (`src/pipeline/validator_poc.py`, `SilverValidatorEngine`). This is a self-contained copy of the W05 Data design; it does not import the collector. It runs these checks in order:
   - natural key, `record_id` type, supported Sysmon IDs (`SUPPORTED_SYSMON_IDS`), timestamp range, and `process_guid` format.
   - deduplication by deterministic `event_id`.
   - routing to one of four Silver lists: process `{1,5}`, file `{11,15,23,26,29}`, registry `{12,13,14}`, network `{3,22}`.
   - anything failing a check goes to `quarantine_dlq` with an `ERR_*` code. Nothing is silently dropped or filled in.

`contract_check.py` sits beside this pipeline. It is a coverage report, not a gate. It compares each Sysmon EventData field against an `EXPECTED` table that records whether the field maps to a Silver column (`in_silver`), is still missing (`missing_in_silver`), or has no table yet (`no_target`).

`src/pipeline/sql/silver_gold_schema_and_views_v1_1.sql` is the DDL for the Silver/Gold schema. Nothing in the Python code executes it; `validator_poc.py` builds its own in-memory DuckDB table.

## Gotchas

- **Duplicated logic.** `validator_poc.py` re-implements `strip_guid`, `parse_iso_utc`, the registry parsing, and the `EDR_NAMESPACE` UUID, rather than importing them from the collector. The two namespace constants must stay identical. `test_01_deterministic_uuidv5_matches_w3_real_samples` in `tests/test_validator_poc_w5.py` checks the validator's IDs against the real W3 samples, so drift between the copies should show up there.
- **Two event-type vocabularies.** The collector emits names like `PROCESS_START` and `REGISTRY_SET_VALUE`. The validator's `EVENT_ID_TO_TYPE_DEFAULT` uses similar but not identical names, e.g. `REGISTRY_RENAME` vs the collector's `REGISTRY_RENAME_KEY`. The collector's source comment marks this as pending decision Q-X3. Don't assume the two sides agree.
- **Zero data fabrication.** Missing fields stay missing, and the validator quarantines records that lack required fields rather than filling defaults. Keep that behavior when you extend the code.
- **Samples are not fully anonymized.** `references/samples/` and the test fixtures contain real-looking host names (e.g. `DESKTOP-IDEMGQU`) and user names. The README asks that they be checked before sharing. Don't publish them, and don't copy them into new public-facing files.
- **Scope of the docs.** `docs/` is written in Vietnamese and is organized by week (`w1`–`w5`) and by topic (`architecture`, `research`, `decisions`, `scope`). The ADRs in `docs/decisions/` record design choices that the code implements; check them before changing the event ID, GUID, or raw-preservation rules (ADR 0001–0003).

## Conventions

- Commit messages follow Conventional Commits with a scope drawn from `docs/conventions/03-commit-convention.md` (e.g. `feat(collector): ...`, `fix(silver): ...`, `docs(architecture): ...`). Reference issues in the footer (`Refs #n`, `Closes #n`).
- Branch names use `<type>/<short-description>` (`feature/`, `fix/`, `docs/`, `research/`, `refactor/`, `chore/`), lowercase with hyphens. See `docs/conventions/02-branch-convention.md`.
