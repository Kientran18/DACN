# DACN — EDR v2 Architecture Diagrams

> **PROPOSAL only** — diagrams describe target design, NOT implemented or integration-tested components.
>
> Architecture specification: [Local EDR Reference Architecture v2](../docs/architecture/local-edr-reference-architecture-v2.md). Baseline: [Preliminary Security Architecture](../docs/architecture/preliminary-security-architecture.md).

## 1. System context: Local EDR, not XDR

~~~mermaid
flowchart LR
 U["Windows User / Applications"] --> OS["Windows 10/11 OS"]
 OS --> SYS["Sysmon Event Log"]
 SYS --> AGENT["Local DACN EDR runtime"]
 AGENT --> DB["Local evidence / alerts / rules"]
 OP["Local Analyst / Administrator"] --> UI["Local UI / CLI"]
 UI --> AGENT
 AGENT -->|Approved actions only| OS
 FUT["Cloud / identity / network / mail feeds"] -.->|"XDR extension: NOT Phase 1"| AGENT
~~~

## 2. Target system component architecture

~~~mermaid
flowchart TB
 subgraph W["ONE WINDOWS ENDPOINT / TRUST DOMAIN"]
  subgraph T["SOURCE LAYER"]
   SYS["Sysmon Windows Event Log"]
   WIN["Security / System Event Log (optional)"]
  end
  subgraph A["COLLECTION + DURABILITY / Software"]
   COL["Collector Reader + Bookmark"]
   BUF["Bounded Queue / Health"]
   RAW["Sealed Canonical Bronze JSONL + SHA Manifest"]
   BOOK["Checkpoint / Replay Ledger"]
  end
  subgraph D["DATA PLANE / Data"]
   VAL["Event-specific Validator + Dedup"]
   BAD["Quarantine / Dead Letter"]
   SIL["Silver DuckDB - 4 event groups"]
   CONTEXT["Process lineage + enrich + temporal features"]
  end
  subgraph CY["DETECTION PLANE / Cyber"]
   IOC["IOC/Hash Matcher"]
   RULE["Rule Evaluator - versioned"]
   COR["Behavioral Correlator"]
   AI["AI Scorer (future optional)"]
   EV["Evaluation / No-data State"]
  end
  subgraph O["OPERATOR / INVESTIGATION"]
   MGR["Alert Manager / Grouping"]
   GOLD["Gold Alerts + Evidence Refs"]
   HUNT["Hunt + Timeline + Process Tree"]
   UI["Local UI / CLI"]
  end
  subgraph R["RESPONSE / gated"]
   POL["Policy + Allowlist + Manual Approval"]
   RES["Privileged Executor (future)"]
   AUD["Audit + Restore metadata"]
  end
  subgraph C["CROSS-CUTTING CONTROL"]
   CONF["Versioned Rules / Config"]
   HEALTH["Service Health / Telemetry Gaps"]
   PRIV["ACL / Privacy / Retention"]
  end
 end
 SYS --> COL
 WIN -.-> COL
 COL --> BUF --> RAW --> VAL
 BOOK <--> COL
 VAL -->|valid| SIL
 VAL -->|invalid| BAD
 BAD -.->|reviewed replay| VAL
 SIL --> CONTEXT
 SIL --> IOC
 SIL --> RULE
 CONTEXT --> COR
 CONTEXT -.-> AI
 IOC --> EV
 RULE --> EV
 COR --> EV
 AI -.-> EV
 EV --> MGR --> GOLD --> HUNT --> UI
 MGR --> POL -->|approval and validation| RES --> AUD
 AUD --> GOLD
 CONF -.-> RULE
 CONF -.-> POL
 HEALTH -.-> COL
 HEALTH -.-> VAL
 HEALTH -.-> EV
 PRIV -.-> RAW
 PRIV -.-> GOLD
~~~

## 3. Sequence: event to alert

~~~mermaid
sequenceDiagram
 participant S as Windows Sysmon
 participant C as Collector (Software)
 participant B as Bronze durable storage
 participant V as Validator (Data)
 participant D as Silver / Features
 participant E as Detection (Cyber)
 participant A as Alert + Analyst
 S->>C: Event XML + channel/record_id/time
 C->>B: append raw_xml + ingest metadata
 B-->>C: segment seal + manifest persisted
 C->>C: advance bookmark/checkpoint
 B->>V: replay sealed segment
 alt invalid record
   V->>V: quarantine with error/source ref
 else valid record
   V->>D: normalized Silver with raw reference
   D->>E: event/features + provenance
   E->>E: single-event/temporal correlation
   alt insufficient or waiting event
     E-->>A: coverage/health state (not confirmed attack)
   else rule match
     E->>A: DetectionResult + contributing_event_ids
     A->>A: group/dedup/triage alert
     A->>D: resolve source event and provenance
   end
 end
~~~

## 4. Sequence: response safety gate

~~~mermaid
sequenceDiagram
 participant AN as Analyst
 participant AL as Alert / Evidence
 participant P as Response Policy + Approval
 participant X as Privileged Executor
 participant OS as Windows OS
 participant AU as Audit / Recovery
 AN->>AL: open alert, check evidence and missing data
 AN->>P: request response action
 P->>P: verify authorization, allowlist, rule status, evidence
 alt denied / incomplete / protected target
   P-->>AN: deny with reason and audit
 else explicit approval
   P->>X: signed/authorized action request
   X->>OS: revalidate process identity/path before action
   alt target changed or OS call fails
     X->>AU: no-op/failure + reason
   else success
     X->>OS: approved terminate/quarantine, when implemented
     X->>AU: actor, action, outcome, recovery pointer
   end
 end
~~~

## 5. Key design constraints

- Dotted edges are future / optional or control paths; solid edges depict planned logical data paths, **not implementation status**.
- No Kafka, no distributed cluster, no cloud dependency for Phase 1.
- **Single writer** for embedded DuckDB; UI/Detection read through snapshot or an API.
- A DetectionResult can be **MATCH, NO_MATCH, INSUFFICIENT_TELEMETRY, PENDING_LATE_EVENTS**; missing telemetry is not proof of safety.
- No automatic destructive response in MVP; audit, policy check and human approval required.
- Persist source identity and immutable raw references; don't fabricate event IDs or process GUIDs.
- Current W03/W05 code is PoC; most boxes are proposed modules.
