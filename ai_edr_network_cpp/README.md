# AI-Enabled EDR — C++ Network Behaviour Analysis Module

A hackathon-oriented **defensive endpoint telemetry prototype** written primarily in C++.

This project observes the network behaviour of a selected Windows process in an isolated lab/sandbox, extracts behavioural features, applies transparent heuristic rules, and optionally sends the resulting summary to an AI-analysis layer.

> **Safety notice:** Analyse unknown executables only inside an isolated, disposable environment that you own and control. Do not run suspicious samples on your normal machine or production network.

---

## 1. Architecture

```text
Target executable
       |
       v
Isolated Windows VM / Sandbox
       |
       v
Process-aware network collector
       |
       v
Connection events
       |
       +------------------------+
       |                        |
       v                        v
Feature extraction         Rule engine
       |                        |
       +-----------+------------+
                   |
                   v
          Structured analysis
                   |
                   v
      Optional AI / Gemini adapter
                   |
                   v
             JSON report
```

The design principle is:

> **Collectors observe facts. Feature extraction summarizes facts. Rules calculate deterministic signals. AI explains the combined evidence.**

The AI layer should not be the only security decision-maker.

---

## 2. Repository Structure

```text
ai_edr_network_cpp/
├── README.md
├── CMakeLists.txt
├── .env.example
├── config/
│   └── default.json
├── include/
│   ├── models.hpp
│   ├── config.hpp
│   ├── collector.hpp
│   ├── features.hpp
│   ├── rules.hpp
│   ├── report.hpp
│   └── gemini_client.hpp
├── src/
│   ├── main.cpp
│   ├── config.cpp
│   ├── collector.cpp
│   ├── features.cpp
│   ├── rules.cpp
│   ├── report.cpp
│   └── gemini_client.cpp
├── tests/
│   └── test_features.cpp
└── data/
    └── reports/
```

---

# 3. What the MVP collects

For a selected Windows process ID:

- PID
- Process name
- Local IP/port
- Remote IP
- Remote port
- TCP/UDP protocol
- TCP state
- Observation timestamp

Example event:

```json
{
  "timestamp": "2026-08-26T10:00:00Z",
  "pid": 1234,
  "process_name": "example.exe",
  "local_ip": "192.168.1.20",
  "local_port": 51521,
  "remote_ip": "203.0.113.10",
  "remote_port": 443,
  "protocol": "TCP",
  "state": "ESTABLISHED"
}
```

The current Windows collector uses the IP Helper API:

- `GetExtendedTcpTable`
- `GetExtendedUdpTable`

This allows the prototype to associate socket ownership with a Windows PID.

---

# 4. Feature Extraction

Raw observations are converted into features such as:

```text
Total observations
Unique remote IPs
Unique remote ports
TCP observations
UDP observations
Repeated endpoints
Approximate periodic endpoints
```

### Example periodic pattern

```text
10:00:00 -> 203.0.113.10:443
10:00:10 -> 203.0.113.10:443
10:00:20 -> 203.0.113.10:443
10:00:30 -> 203.0.113.10:443
```

The feature extractor calculates the intervals and their relative variation.

A regular pattern is **not proof of malware**. It is only a signal that may be useful when combined with other evidence.

---

# 5. Rule Engine

The local rule engine currently checks for:

### Possible periodic outbound activity

Repeated observations at relatively regular intervals.

### Repeated remote endpoint

The process repeatedly communicates with the same remote endpoint.

### High destination diversity

The process contacts many distinct remote IPs during a short observation period.

The score is capped at 100:

```text
0–39   LOW / UNKNOWN
40–69  MEDIUM
70–100 HIGH
```

These values are intentionally simple for a hackathon MVP. Tune them using benign and controlled test data.

---

# 6. Building on Windows

## Requirements

- Windows 10 or Windows 11
- Visual Studio 2022 with C++ Desktop Development
- CMake 3.20+
- C++17 compiler

The Windows networking collector uses:

```text
iphlpapi.lib
ws2_32.lib
```

## Build

Open a Developer PowerShell for Visual Studio:

```powershell
git clone <your-repository-url>
cd ai_edr_network_cpp

cmake -S . -B build
cmake --build build --config Release
```

Run:

```powershell
.\build\Release\edr_network.exe --pid 1234 --duration 60
```

Depending on process permissions, run the terminal with appropriate privileges for processes you are authorised to analyse.

---

# 7. Configuration

`config/default.json`

```json
{
  "collection": {
    "sample_interval_seconds": 1,
    "default_duration_seconds": 60
  },
  "analysis": {
    "beacon_min_observations": 4,
    "beacon_max_relative_interval_std": 0.20,
    "repeated_endpoint_threshold": 5
  },
  "output": {
    "report_directory": "data/reports"
  }
}
```

---

# 8. Optional Gemini Integration

The repository contains a `GeminiClient` interface.

The network module creates a compact JSON report like:

```json
{
  "process_name": "example.exe",
  "network_features": {
    "unique_remote_ips": 3,
    "repeated_endpoints": [
      "203.0.113.10:443"
    ]
  },
  "rule_findings": [],
  "local_risk_score": 25
}
```

The Gemini client is deliberately an **adapter layer**.

This makes it easy to change from:

```text
Local C++ EDR
       |
       v
GeminiClient
       |
       v
Gemini API
```

to another provider or a local model later.

### Important

Do not hard-code an API key.

Use an environment variable:

```text
GEMINI_API_KEY
```

For a production implementation, use a proper HTTP/TLS client and JSON parser such as:

- libcurl
- Boost.Beast
- nlohmann/json

The included `GeminiClient` currently creates the analysis request payload but intentionally leaves network API transport as a clearly marked integration point. This keeps the security-sensitive API boundary separate from telemetry collection.

---

# 9. Current Limitations

This is an MVP, not a production EDR.

- Short-lived connections may be missed because this prototype polls tables.
- DNS queries are not yet reliably attributed to individual processes.
- TLS payloads are not decrypted.
- IPv6 collection is not yet implemented in the MVP.
- No threat-intelligence reputation lookup is included.
- No automatic containment/blocking is enabled.
- AI API transport is an adapter placeholder.

---

# 10. Recommended Next Upgrades

## Phase 1 — Complete the collector

- IPv6
- Process creation tracking
- Better timestamps
- Connection lifecycle events

## Phase 2 — DNS attribution

Capture:

```text
Process
PID
Domain
Resolved IP
Timestamp
Query type
```

## Phase 3 — ETW

Use Windows Event Tracing for Windows for higher-fidelity event-driven telemetry.

## Phase 4 — WFP

Use Windows Filtering Platform for controlled enforcement and network containment.

## Phase 5 — AI integration

Send only summarized telemetry to the model.

Use structured output:

```json
{
  "verdict": "benign | suspicious | malicious | unknown",
  "confidence": 0,
  "risk_score": 0,
  "summary": "",
  "key_findings": [],
  "recommended_action": "allow | monitor | isolate | investigate"
}
```

## Phase 6 — Full EDR correlation

Combine:

```text
Static file features
       +
Process behaviour
       +
File operations
       +
Registry activity
       +
Network activity
       =
Final EDR assessment
```

---

# 11. Suggested Hackathon Demo

Use a **known benign program first** to demonstrate collection.

```text
1. Start isolated VM
2. Start a test process that makes network connections
3. Obtain its PID
4. Start EDR collector
5. Collect for 30–60 seconds
6. Generate report
7. Show features and rule findings
8. Optionally send summary to Gemini
9. Display final assessment
```

For demonstrations involving suspicious samples, use only approved, controlled training/lab procedures and a disposable isolated environment.

---

# 12. Important Design Decision

Do not implement this:

```text
Raw packets
    |
    v
Gemini
    |
    v
Malware / Benign
```

Prefer:

```text
Events
  |
  v
Feature extraction
  |
  v
Deterministic rules/statistics
  |
  v
Compact evidence summary
  |
  v
AI reasoning
  |
  v
Final analyst-oriented report
```

This is more explainable, cheaper, easier to debug, and better suited to an EDR architecture.
