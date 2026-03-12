# Reconesis Demo Lab

This directory contains a pre-configured Docker network environment designed to test and demonstrate **Reconesis** safely, without scanning live networks.

## Architecture

The lab creates an isolated Docker bridge network (`172.20.0.0/24`) with **20 containers** across three tiers: 7 critical infrastructure assets, 5 standard hosts, and 8 noise nodes.

---

### Tier 1 — Critical Assets (should be flagged CRITICAL or HIGH)

| Container | IP Address | Simulated Identity | Exposed Services |
| :--- | :--- | :--- | :--- |
| `demo_db_postgres` | `172.20.0.10` | PostgreSQL Database | PostgreSQL (5432) |
| `demo_db_mysql` | `172.20.0.11` | MySQL Database | MySQL (3306) |
| `demo_db_redis` | `172.20.0.12` | Redis Cache/DB | Redis (6379) |
| `demo_db_mongo` | `172.20.0.13` | MongoDB | MongoDB (27017) |
| `demo_mail_server` | `172.20.0.14` | Mail Server | SMTP (25), POP3 (110), IMAP (143), Submission (587) |
| `demo_router_core` | `172.20.0.15` | Core Router | SSH (22), Telnet (23), SNMP (161), BGP (179) |
| `demo_firewall_edge` | `172.20.0.16` | Edge Firewall | SSH (22), HTTPS (443), Admin (8443) |

### Tier 2 — Standard Hosts (should score MEDIUM or LOW)

| Container | IP Address | Simulated Identity | Exposed Services |
| :--- | :--- | :--- | :--- |
| `demo_web_frontend` | `172.20.0.20` | Nginx Web Server | HTTP (80) |
| `demo_app_server` | `172.20.0.21` | Application Server | HTTP (80), HTTP (8080) |
| `demo_jumpbox` | `172.20.0.22` | Bastion / Jump Host | SSH (22) |
| `demo_monitoring` | `172.20.0.23` | Grafana + Prometheus | SSH (22), Grafana (3000), Prometheus (9090) |
| `demo_ldap_server` | `172.20.0.24` | Active Directory / LDAP | LDAP (389), LDAPS (636) |

### Tier 3 — Noise (should score LOW and be deprioritised)

| Container | IP Address | Simulated Identity | Exposed Services |
| :--- | :--- | :--- | :--- |
| `demo_workstation_1` | `172.20.0.30` | Corporate Workstation | HTTP (80) |
| `demo_workstation_2` | `172.20.0.31` | Corporate Workstation | HTTP (80) |
| `demo_workstation_3` | `172.20.0.32` | Corporate Workstation | HTTP (80) |
| `demo_workstation_4` | `172.20.0.33` | Corporate Workstation | HTTP (80) |
| `demo_workstation_5` | `172.20.0.34` | Corporate Workstation | HTTP (80) |
| `demo_workstation_6` | `172.20.0.35` | Corporate Workstation | HTTP (80) |
| `demo_printer_1` | `172.20.0.40` | Network Printer | HTTP (80) |
| `demo_printer_2` | `172.20.0.41` | Network Printer | HTTP (80) |

---

## How to Run the Demo (Ubuntu)

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
First run downloads images — may take a few minutes.

### 2. Verify the Lab is Running
```bash
docker ps | grep demo_
# Should show 20 containers
```

### 3. Run Reconesis (CLI)
From the project root:
```bash
source venv/bin/activate
sudo venv/bin/python main.py --target 172.20.0.0/24 --verbose
```
> **Note:** `sudo` is required because Nmap needs raw socket access for SYN scans on Linux.

### 4. Run Reconesis (Dashboard)
For a visual demo with live scan visibility:
```bash
source venv/bin/activate
sudo venv/bin/python dashboard.py
# Open http://localhost:5000 in your browser
# Enter target: 172.20.0.0/24
```

### 5. Stop the Lab
```bash
cd demo_lab
docker-compose down
```

---

## Expected Reconesis Output

When pointed at `172.20.0.0/24`, Reconesis should:

1. **Scout Mode** — sweep the `/24` subnet and discover all 20 live containers.
2. **Port Scan & Classification** — run targeted port scans and classify each host:
   - `172.20.0.10` → **CRITICAL** — Database Server (PostgreSQL 5432)
   - `172.20.0.11` → **CRITICAL** — Database Server (MySQL 3306)
   - `172.20.0.12` → **CRITICAL** — Database Server (Redis 6379)
   - `172.20.0.13` → **CRITICAL** — Database Server (MongoDB 27017)
   - `172.20.0.14` → **CRITICAL** — Mail Server (SMTP + POP3 + IMAP + Submission)
   - `172.20.0.15` → **CRITICAL** — Router (SSH + Telnet + SNMP + BGP)
   - `172.20.0.16` → **CRITICAL** — Firewall (SSH + HTTPS + Admin)
   - `172.20.0.20–.24` → **MEDIUM/LOW** — Standard hosts (web, app, jump, monitoring, LDAP)
   - `172.20.0.30–.35` → **LOW** — Workstation noise (port 80 only)
   - `172.20.0.40–.41` → **LOW** — Printer noise (port 80 only)
3. **Hunter Mode** — execute deep targeted scans against the 7 critical assets using type-specific prompts (Database, Mail, Router/Firewall).
4. **Report** — `scan_report.md` should mention all 4 database technologies (PostgreSQL, MySQL, Redis, MongoDB) plus mail server, router, and firewall findings.

---

## Output Files

After scanning, collect from the project root:
- `scan_results.json` — TOON-formatted structured scan data
- `scan_report.md` — AI-generated Markdown vulnerability report
- `reconesis.log` — Full run log with timing and depth metrics
