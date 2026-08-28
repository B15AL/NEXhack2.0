# AI EDR Network Analyzer — Raw Telemetry + Gemini

Cross-platform C++17 defensive prototype for sandbox network-behaviour analysis.

## Design

This version deliberately uses **Gemini as the primary interpreter of the raw network report**:

```text
Sandboxed process
      |
      v
Platform network collector
      |
      v
Raw connection observations
      |
      v
JSON network report
      |
      v
Gemini API
      |
      v
Structured AI verdict
```

The local C++ code collects and serializes observations. It does not make the final malware decision locally.

> Use only on systems/processes you own or are authorized to monitor. Execute unknown software only inside an isolated, disposable sandbox.

## Platforms

- Windows: Windows IP Helper API, IPv4 TCP table
- Linux: `/proc/<pid>/net/tcp` and `/udp`
- macOS: `lsof`
- C++17 + CMake

This is a hackathon MVP. Production EDRs should use event-driven telemetry such as ETW/WFP, eBPF, and macOS EndpointSecurity/Network Extension.

## Requirements

- CMake >= 3.16
- C++17 compiler
- libcurl
- Gemini API key for AI mode

### Ubuntu/Debian

```bash
sudo apt update
sudo apt install cmake g++ libcurl4-openssl-dev
```

### macOS

```bash
brew install cmake curl
```

### Windows

Install CMake and a C++ compiler. With vcpkg:

```powershell
vcpkg install curl:x64-windows
```

Configure with the vcpkg toolchain as appropriate for your installation.

## Build

Linux/macOS:

```bash
cmake -S . -B build
cmake --build build -j
```

Windows:

```powershell
cmake -S . -B build
cmake --build build --config Release
```

## Run without Gemini

Demo mode uses synthetic observations and makes no network connection:

```bash
./build/edr_network --demo
```

Windows:

```powershell
.\build\Release\edr_network.exe --demo
```

## Configure Gemini

Do **not** put the API key in C++ source or commit it.

Linux/macOS:

```bash
export GEMINI_API_KEY="YOUR_KEY_HERE"
```

PowerShell:

```powershell
$env:GEMINI_API_KEY="YOUR_KEY_HERE"
```

The program reads the environment variable at runtime.

## Run AI mode

Synthetic test:

```bash
./build/edr_network --demo --ai
```

Real authorized/sandboxed process:

```bash
./build/edr_network --pid 12345 --duration 30 --ai
```

The `--no-ai` switch explicitly disables the API call.

## What gets sent to Gemini?

The AI mode sends a compact JSON payload containing the **raw network observations**, including:

- timestamp
- PID
- process name
- local IP/port where available
- remote IP/port
- protocol
- connection state

Example:

```json
{
  "process": {
    "pid": 99999,
    "name": "demo_process"
  },
  "observations": [
    {
      "timestamp": "2026-08-28T12:00:00Z",
      "protocol": "TCP",
      "remote_ip": "203.0.113.10",
      "remote_port": 443,
      "state": "ESTABLISHED"
    }
  ]
}
```

The report is accompanied by a prompt telling Gemini to act as a defensive network-behaviour analyst.

## Gemini output

The application asks Gemini for JSON in this shape:

```json
{
  "verdict": "malicious|suspicious|benign|inconclusive",
  "confidence": 0.0,
  "reasoning": [
    "..."
  ],
  "network_indicators": [
    "..."
  ],
  "possible_behaviors": [
    "..."
  ],
  "recommendation": "..."
}
```

The AI result is embedded into the final report under:

```json
"ai_assessment": {}
```

## Important interpretation rule

Network behaviour alone does **not** prove that an executable is malware.

For example:

- HTTPS to a common cloud service can be benign.
- Periodic connections can be normal application polling.
- An unusual port can be legitimate.
- A suspicious IP can be shared infrastructure.

The AI prompt explicitly asks Gemini to distinguish observations from conclusions and to use `inconclusive` when network evidence is insufficient.

For a real EDR, combine this module with:

```text
Static analysis
+
Process behaviour
+
File behaviour
+
Persistence behaviour
+
Network behaviour
+
AI reasoning
```

## Testing

```bash
ctest --test-dir build --output-on-failure
```

The unit test validates raw-report serialization and demo telemetry.

## Reports

Reports are written to:

```text
data/reports/
```

## Gemini model

The code uses a configurable environment variable:

```text
GEMINI_MODEL
```

Default:

```text
gemini-2.5-flash
```

You can override it:

```bash
export GEMINI_MODEL="gemini-2.5-flash"
```

This keeps the model choice outside the source code.

## Security/privacy

Do not send:

- executable contents
- passwords
- private keys
- personal data
- packet payloads

unless your project explicitly requires it and your test environment permits it.

This module focuses on connection metadata. For a production product, establish a clear telemetry/data-retention policy before sending endpoint telemetry to an external AI service.

## Future improvements

1. DNS query collection
2. Domain names associated with connections
3. IPv6 collection
4. Connection lifecycle events
5. TLS metadata such as SNI where legitimately available
6. IP/domain reputation enrichment
7. Event-driven collection
8. Proper JSON library instead of the small built-in serializer
9. Gemini structured-output/schema validation
10. Correlation with static/process/file telemetry
