# Preliminary Security Architecture

## 1. Sơ đồ kiến trúc gốc

Luồng trong sơ đồ:

```text
Windows Endpoint
      ↓
Event Collection Layer
      ↓
Process Events / File Events / Registry Events / Network and DNS Events
      ↓
Event Normalization
      ↓
Detection Engine
      ↓
Signature-based / Rule-based / Behavioral Detection
      ↓
Alert
      ↓
Investigation ↔ Response
```

## 2. Biểu diễn bằng Mermaid

```mermaid
flowchart TD
    A[Windows Endpoint] --> B[Event Collection Layer]
    B --> C1[Process Events]
    B --> C2[File Events]
    B --> C3[Registry Events]
    B --> C4[Network and DNS Events]
    C4 --> D
    C1 --> D[Event Normalization]
    C2 --> D
    C3 --> D
    D --> E[Detection Engine]
    E --> F1[Signature-based Detection]
    E --> F2[Rule-based Detection]
    E --> F3[Behavioral Detection]
    F1 --> G[Alert]
    F2 --> G
    F3 --> G
    G --> H[Investigation]
    G --> I[Response]
```

## 3. Investigation output trong sơ đồ

- Event Timeline
- Process Tree Visualizer
- Detailed File Information
- Rule Evidence

## 4. Response output trong sơ đồ

- Terminate Malicious Process
- Quarantine File
- Block File Hash
- Update Whitelist

## 5. System Boundary trong Threat Model

```text
┌──────────────── Windows Endpoint ────────────────┐
│ User                                             │
│   ↓                                              │
│ Applications / Processes                         │
│   ↓                                              │
│ Windows OS                                       │
│   ├── Process Events                             │
│   ├── File Events                                │
│   ├── Registry Events                            │
│   └── Network Events                             │
│   ↓                                              │
│ Security Collector                               │
│   ↓                                              │
│ Detection Engine                                 │
│   ├── Signature Database                         │
│   └── Behavior Rules                             │
│   ↓                                              │
│ Alert                                            │
│   ├── Investigation                              │
│   └── Response                                   │
└──────────────────────────────────────────────────┘
```
