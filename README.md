# NEXhack2.0 — AI-Powered EDR (Prototype)

An AI-assisted Endpoint Detection & Response (EDR) prototype built for a hackathon. Traditional EDR/AV tools rely heavily on static signatures and hard-coded heuristics, which modern malware routinely evades through obfuscation, API hashing, injection, and other anti-analysis tricks. This project explores a different approach: run several independent, narrowly-scoped **static** analyzers over a Windows executable, have an AI model (Gemini) reason over each analyzer's evidence, and have each module emit its own **threat score**.

> ⚠️ **Prototype disclaimer:** This is proof-of-concept code from a hackathon, not a production security product. Scores are explainable heuristics, not calibrated malware probabilities. The suspicious `.exe`/`.zip` files in this repo are included strictly for controlled local testing and are never executed by any part of this codebase.

---

## Core Idea

Modern malware hides from traditional EDR/AV by using techniques such as:
- Obfuscated or packed code
- API hashing (resolving Windows APIs at runtime instead of importing them normally, so static import tables look clean)
- Process injection and other native-API tricks
- Network communication with attacker infrastructure
- Signatures that don't match known malware databases

Instead of one monolithic detector, this project splits the problem across **independent analyzer modules**, each responsible for one angle of evidence. Each module:
1. Statically extracts structured evidence from the target file (it never executes the file).
2. Sends that evidence — never raw untrusted instructions — to a Gemini model as **data**.
3. Gets back a structured JSON verdict for its specific angle, including a **0–100 risk score**.

## Current Stage (this prototype)

Right now, each module works **independently** and outputs its own threat score. There is no unified verdict yet — that's the next stage (see [Roadmap](#roadmap)).

## Analyzer Modules

| Module | File(s) | What it does | Output |
|---|---|---|---|
| **API Hashing Analysis** | `api_hash_ana.py` | Parses the PE file, disassembles executable sections, extracts immediate values that could be hash constants, detects hash-loop patterns, and matches them against a curated Windows API catalogue using common hashing algorithms (ROR13, ROR7, DJB2, SDBM, FNV-1a, CRC32, etc.). Sends the deterministic candidate matches to Gemini, which decides whether real API-hashing is present, infers the likely algorithm, reconstructs a possible static call order, and infers suspected behaviors from supported API combinations. | JSON with `hashing_detected`, `likely_hash_algorithm`, `recovered_api_candidates`, `possible_static_api_order`, `suspected_behaviours`, `risk_score_0_to_100`, `risk_label`, `risk_reasons`, `summary` |
| **Obfuscation / Deobfuscation** | `OBFUSCATORAI.c` | Uploads the target executable (capped to a byte budget to stay under the model's token limit) to the Gemini Files API using resumable upload over `libcurl`, then asks Gemini to statically deobfuscate/reconstruct pseudocode, describe behavior, flag suspicious indicators, and produce a risk score — all without ever running the file. | `gemini_result.json` containing obfuscation notes, pseudocode/behavior summary, suspicious indicators, and a risk score |
| **Networking Analysis** | `ai_edr_network_gemini_raw/` | Examines the executable's networking-related indicators (e.g. embedded IPs/domains, network API usage) with AI assistance to judge whether the sample is likely to reach out to attacker-controlled infrastructure or known-malicious domains. | Network-focused threat assessment |
| **Signature Analysis** | `analyzer` | Compares the sample against known/current malware signatures with AI assistance to estimate similarity to known malware families. | Signature-based likelihood score |
| **Behavioral Analysis** | `malware_analyzer/` (Flask web server + CLI) | The main orchestration layer that `run.py` launches — a web server (`malware_analyzer.app`) and CLI (`malware_analyzer.cli`) for interactive file analysis and reporting. | Report written to `reports/` |

Each module was originally scoped and researched independently by a different team member (see `Nexhack2.0.txt` for the original task breakdown), then wired together behind the shared entry point.

## How Scoring Works Today

Every module follows the same pattern:

```
target.exe
   │
   ▼
Local static extraction (no execution)
   │  (imports, sections, entropy, disassembly,
   │   hash candidates, network indicators, signatures, etc.)
   ▼
Structured evidence bundle (JSON)
   │
   ▼
Gemini model  ──►  reasons ONLY over the evidence bundle,
                    which is explicitly marked as untrusted
                    DATA, never instructions
   │
   ▼
Structured AI verdict for that module
   (risk_score_0_to_100, risk_label, reasons, summary)
```

Each module currently prints/saves its own score independently — there is no cross-module fusion yet.

## Roadmap

The next stage of this project is a **second-stage aggregator model**:

1. Run all analyzer modules against the same target file.
2. Collect each module's structured output (score, label, reasons, summary) as evidence.
3. Compose those outputs into a single prompt that is fed to another model.
4. That model reasons across *all* module evidence together and produces one **final, unified threat score/verdict** for the file — weighing agreement/disagreement between modules (e.g. "obfuscation module says high, but no networking or hashing evidence corroborates it").

This turns the current set of independent single-signal scorers into a proper multi-signal AI triage pipeline.

## Getting Started

### Requirements
See `requirements.txt`. Key dependencies:
- `pefile`, `capstone` — PE parsing & disassembly
- `google-generativeai` — Gemini API client (Python modules)
- `libcurl` — used by `OBFUSCATORAI.c` for the Gemini Files API
- `flask`, `waitress` — web server for behavioral analysis
- `yara-python`, `androguard`, `oletools`, `ppdeep` — supporting static-analysis tooling

Install Python dependencies:
```bash
pip install -r requirements.txt
```

Set your Gemini API key before running any module:
```bash
# PowerShell
$env:GEMINI_API_KEY="YOUR_KEY"

# bash/zsh
export GEMINI_API_KEY="YOUR_KEY"
```

### Running

The shared entry point is `run.py`:
```bash
python run.py
```
This gives you a menu to:
1. **Start Web Server** (recommended) — launches the behavioral analysis web UI.
2. **Run Interactive CLI Analysis** — analyze a single file from the command line; results are written to `reports/`.
3. Exit

Individual modules can also be run standalone, e.g.:
```bash
# API hashing analysis, with a demo (no real file needed)
python api_hash_ana.py --demo

# API hashing analysis on a real PE file
python api_hash_ana.py path\to\sample.exe --json out.json
```

## Repository Layout

```
NEXhack2.0/
├── run.py                     # Shared entry point / menu
├── api_hash_ana.py            # API-hashing analyzer module
├── OBFUSCATORAI.c             # Obfuscation/deobfuscation analyzer module
├── ai_edr_network_gemini_raw/ # Networking analyzer module
├── analyzer                   # Signature analyzer module (compiled)
├── malware_analyzer/          # Behavioral analysis module (web server + CLI)
├── reports/                   # Generated analysis reports
├── tests/                     # Test files
├── gemini_result.json         # Example obfuscation-module output
├── requirements.txt
└── Nexhack2.0.txt             # Original team research/task breakdown
```

## Safety Notes

- **No sample in this repository is ever executed** by the analysis code — all analysis is static (PE parsing, disassembly, byte/string inspection, file upload for AI review).
- Test binaries included in the repo (e.g. `malware.exe`) are for controlled local testing only — do not run them.
- AI risk scores are explainable heuristics intended to assist a human analyst, and are explicitly *not* framed as a calibrated probability of maliciousness.
