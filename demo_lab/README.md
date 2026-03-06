# Reconesis Demo Lab

This directory contains a pre-configured Docker network environment designed specifically to test and demonstrate the capabilities of **Reconesis** safely, without scanning live networks.

## Architecture

The lab creates an isolated Docker bridge network (`172.20.0.0/24`) containing **10 distinct targets** — 4 critical infrastructure assets, 2 standard hosts, and 4 workstation "noise" nodes:

### Critical Assets (Should be flagged by Reconesis)

| Container | IP Address | Simulated Identity | Exposed Services |
| :--- | :--- | :--- | :--- |
| `demo_db_server` | `172.20.0.10` | Database Server | PostgreSQL (5432) |
| `demo_mail_server` | `172.20.0.11` | Mail Server | SMTP (25) |
| `demo_router` | `172.20.0.14` | Router | SSH (22), Telnet (23), SNMP (161) |
| `demo_firewall` | `172.20.0.15` | Firewall | SSH (22), HTTPS (443), Admin (8443) |

### Standard Hosts

| Container | IP Address | Simulated Identity | Exposed Services |
| :--- | :--- | :--- | :--- |
| `demo_web_server` | `172.20.0.12` | Web Server | HTTP (80) |
| `demo_generic_host` | `172.20.0.13` | Standard Linux Host | SSH (22) |

### Noise Targets (Should be ignored by Reconesis)

| Container | IP Address | Simulated Identity | Exposed Services |
| :--- | :--- | :--- | :--- |
| `demo_workstation_1` | `172.20.0.20` | Workstation | HTTP (80) |
| `demo_workstation_2` | `172.20.0.21` | Workstation | HTTP (80) |
| `demo_workstation_3` | `172.20.0.22` | Workstation | HTTP (80) |
| `demo_workstation_4` | `172.20.0.23` | Workstation | HTTP (80) |

---

## 🚀 How to Run the Demo (Ubuntu)

### Prerequisites
Run the setup script from the project root (one-time):
```bash
chmod +x setup.sh
./setup.sh
```
This installs `nmap`, `docker`, `docker-compose`, and Python dependencies.

### 1. Start the Lab
```bash
cd demo_lab
docker-compose up -d
```
*(First run downloads images — may take a minute.)*

### 2. Verify the Lab is Running
```bash
docker ps
# Should show 10 containers
```

### 3. Run Reconesis (CLI)
From the project root:
```bash
source venv/bin/activate
sudo python3 main.py --target 172.20.0.0/24
```
> **Note:** `sudo` is required because Nmap needs raw socket access for SYN scans on Linux.

### 4. Run Reconesis (Dashboard)
For a visual demo with live scan visibility:
```bash
source venv/bin/activate
sudo python3 dashboard.py
# Open http://localhost:5000 in your browser
# Enter target: 172.20.0.0/24
```

### 5. Stop the Lab
```bash
docker-compose down
```

## What to Expect in the Demo

When you point Reconesis at `172.20.0.0/24`:

1. **Scout Mode** will sweep the `/24` subnet and discover all 10 live containers.
2. The agent will run a port scan against all 10 IPs.
3. The `CriticalityAssessor` will correctly:
   - Flag `172.20.0.10` as **Database Server** (port 5432)
   - Flag `172.20.0.11` as **Mail Server** (port 25)
   - Flag `172.20.0.14` as **Router** (ports 22+23+161)
   - Flag `172.20.0.15` as **Firewall** (ports 22+443+8443)
   - Classify workstations as **LOW** (only port 80 — not critical)
4. **Hunter Mode** will execute targeted deeper scans specifically against the 4 critical assets.
5. A final `scan_report.md` will be generated highlighting the critical infrastructure detected.

## Paper Evaluation Data

After running the demo, collect:
- `scan_results.json` — TOON-formatted structured output
- `scan_report.md` — AI-generated risk report
- Console output — Time-per-host, packet count, depth metrics
