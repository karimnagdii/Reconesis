<div align="center">
  <img src="https://raw.githubusercontent.com/FortAwesome/Font-Awesome/6.x/svgs/solid/satellite-dish.svg" width="80" alt="Reconesis Icon"/>
  <h1>Reconesis</h1>
  <p><strong>An Adaptive Agentic Tool for Autonomous Network Reconnaissance</strong></p>

  <p>
    <a href="#about">About</a> •
    <a href="#features">Features</a> •
    <a href="#architecture">Architecture</a> •
    <a href="#installation">Installation</a> •
    <a href="#usage">Usage</a> •
    <a href="#demo-lab">Demo Lab</a> •
    <a href="#configuration">Configuration</a>
  </p>
</div>

---

## About

**Reconesis** is an agentic network reconnaissance tool that pairs Nmap with a Groq-hosted LLM (Llama 3.3 70B) to autonomously execute an **Observe-Orient-Decide-Act (OODA)** loop.

Unlike static scripts that generate noise and alert fatigue, Reconesis contextually analyzes live scan findings, classifies discovered hosts against 12 infrastructure profiles, and adapts its scanning strategy on the fly — pivoting from broad network sweeps into deep, vulnerability-specific investigations against high-value targets, then producing a Markdown report.

---

## Features

- **Recursive Agentic Execution** — A context-aware LLM state machine that dynamically generates its own Nmap commands based on prior scan feedback, eliminating hardcoded playbooks.
- **TOON Middleware** — Converts raw Nmap XML into **Target-Oriented Object Notation (TOON)**, a token-optimized host representation that feeds cleanly into LLM context windows. Includes SHA-256 hash saturation detection to prevent redundant loops.
- **12-Profile Criticality Engine** — A weighted multi-signal scorer classifying every host against: Database Server, Mail Server, Router, Firewall, Active Directory/LDAP, Jump Host, Web Server, Application Server, NAS Appliance, Windows File Server, DNS Server, and IoT Camera. Signals include port combos, service names, product strings, and OS fingerprints.
- **Context-Aware Prompt Switching** — Automatically transitions from fast "Scout Mode" sweeps (Phase 1–2) into targeted "Hunter Mode" (Phase 3) using asset-specific prompts with NSE vulnerability scripts (`vulners`, `smtp-open-relay`, `ldap-search`, etc.).
- **Non-Blocking Execution with SSE Heartbeats** — Nmap runs via `Popen` with live stdout polling and drain threads. The dashboard receives real-time heartbeat events while long scans are in progress, preventing pipe-buffer deadlocks.
- **Real-Time Web Dashboard** — Flask + Server-Sent Events interface showing phase transitions, live host cards, scan logs, and performance metrics (packets sent, CVEs found, time-to-insight).
- **Adaptive Termination** — Three exit conditions prevent infinite loops: depth exhaustion (`MAX_SUB_ITERATIONS=5`), hash saturation (identical TOON across iterations), and criticality fulfilment (no CRITICAL/HIGH hosts remain).
- **CVE Enrichment** — Deduplicating CVE lookup engine that queries `cve.circl.lu` once per unique product and applies results to all matching hosts.

---

## Architecture

The system has four layers:

### Entry Points
- **`main.py`** — CLI entry point. Validates target IP/CIDR and calls `ReconesisEngine.start_scan()`.
- **`dashboard.py`** — Flask app. Runs `ReconesisEngine` in a background thread and streams events to the browser via SSE at `/stream`. Binds to `0.0.0.0:5000`.

### Core Engine (`src/core/`)

| Module | Class | Role |
|---|---|---|
| `reconesis.py` | `ReconesisEngine` | OODA state machine — orchestrates all 4 phases, manages termination conditions, emits dashboard events |
| `agent.py` | `GroqAgent` | Sends prompt pairs to Groq API; maintains 1 Scout prompt and 4 Hunter prompts (Database, Mail, Router/Firewall, Generic) |
| `executor.py` | `NmapExecutor` | Runs LLM-generated Nmap commands via `Popen`; sanitizes commands, appends `-oX -`, tracks packet counts |
| `toon.py` | `TOONParser` | Parses Nmap XML → TOON host dicts (`target`, `status`, `os`, `ports[]`, `criticality`); computes saturation hash |

### Utilities (`src/utils/`)

| Module | Class | Role |
|---|---|---|
| `criticality.py` | `CriticalityAssessor` | Scores hosts against 12 profiles using weighted signals; thresholds: ≥4 → CRITICAL, ≥2 → HIGH |
| `config.py` | `Config` | Loads `.env`; validates API connectivity before any scan starts |
| `exploit_lookup.py` | `ExploitLookup` | CVE enrichment via vulners NSE output or `cve.circl.lu` fallback |

### Templates
- **`templates/index.html`** — Single-page dashboard. Connects to `/stream` and renders real-time events.

### 4-Phase OODA Loop

```
Phase 1 — Discovery (Scout Mode)
  └─ Aggressive SYN + ICMP sweeps to map live hosts

Phase 2 — Port Scan & Classification (Scout Mode)
  └─ Service enumeration → CriticalityAssessor scores every host
  └─ Filters out low-value noise (workstations, printers, VoIP)

Phase 3 — Hunter Mode (Deep Scan)
  └─ Asset-type-specific LLM prompt selected per critical target
  └─ NSE vulnerability scripts injected (vulners, smtp-open-relay, etc.)

Phase 4 — Report
  └─ AI evaluates aggregated TOON data → Markdown vulnerability report
```

---

## Installation

Requires Python 3.9+, Nmap, and Docker (for the demo lab).

### Ubuntu / Debian Quick Start

```bash
chmod +x setup.sh && ./setup.sh
# Edit .env and set GROQ_API_KEY
```

### Manual Installation

```bash
git clone https://github.com/karimnagdii/Reconesis.git
cd Reconesis
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # then set GROQ_API_KEY
```

Get a free Groq API key at [console.groq.com/keys](https://console.groq.com/keys).

---

## Usage

All commands require `sudo` on Linux — Nmap needs raw socket access for SYN scans.

### Web Dashboard (Recommended)

```bash
source venv/bin/activate
sudo venv/bin/python dashboard.py
# Open http://localhost:5000
```

### CLI

```bash
source venv/bin/activate
sudo venv/bin/python main.py --target 192.168.1.0/24
sudo venv/bin/python main.py --target 192.168.1.0/24 --verbose
```

### Output Files

| File | Contents |
|---|---|
| `scan_results.json` | TOON-formatted structured scan data |
| `scan_report.md` | AI-generated Markdown vulnerability report |
| `reconesis.log` | Persistent log (appended each run) |

---

## Demo Lab

Reconesis ships with an isolated Docker environment for safe testing without scanning live networks.

The lab creates a `172.20.0.0/24` bridge network with **31 containers** across 8 tiers covering all 12 classification profiles, including intentional misconfigurations that NSE scripts can detect:

| Tier | Hosts | Profiles |
|---|---|---|
| Databases | `.10–.13` | PostgreSQL, MySQL, Redis (no-auth), MongoDB |
| Network Infra | `.20–.23` | Router (SNMP public), Firewall, Jump Host, LDAP (anon bind) |
| Services | `.30–.33` | Web Server, App Server (Tomcat), Mail (open relay), DNS (zone xfer) |
| Storage | `.40–.41` | NAS (anon Samba), Windows File Server (SMB signing off) |
| IoT Cameras | `.50–.51` | HikVision, Dahua |
| Workstations | `.60–.65` | Standard + dev workstations (noise nodes) |
| Printers | `.70–.72` | Printers + copier (noise nodes) |
| Specialty Noise | `.80–.85` | VoIP, switch, UPS, video conferencing, access controller |

```bash
# Start
cd demo_lab && docker-compose up -d

# Verify (should print 31)
docker ps | grep demo_ | wc -l

# Run scan
sudo venv/bin/python main.py --target 172.20.0.0/24 --verbose

# Stop
cd demo_lab && docker-compose down
```

See [demo_lab/README.md](demo_lab/README.md) for the full container breakdown, expected criticality scores, and known classification edge cases.

---

## Configuration

All settings are in `src/utils/config.py`, loaded from `.env`.

| Variable | Default | Description |
|---|---|---|
| `GROQ_API_KEY` | — | **Required.** Groq API key |
| `GROQ_MODEL` | `llama-3.3-70b-versatile` | Model to use |
| `GROQ_API_URL` | Groq OpenAI-compat endpoint | Override API base URL |
| `MAX_SUB_ITERATIONS` | `5` | Hard cap on mini-loop passes per depth |
| `DEFAULT_TIMEOUT` | `300` | Timeout in seconds (note: executor timeout is hardcoded separately in `executor.py`) |

---

<div align="center">
  <small>Developed for AI-Driven Defensive Security Operations</small>
</div>
