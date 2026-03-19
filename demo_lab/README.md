# Reconesis Demo Lab

This directory contains a pre-configured Docker network environment designed to test and demonstrate **Reconesis** safely, without scanning live networks.

## Architecture

The lab creates an isolated Docker bridge network (`172.20.0.0/24`) with **31 containers** across eight tiers covering all 12 Reconesis classification profiles. Real services handle containers where Nmap `-sV` fingerprinting must work correctly; the rest use `alpine:3.19` + `socat` for banner-level classification signals.

---

### Tier 1 — Databases (172.20.0.10–.13)

| Container | IP | Profile | Services | Misconfiguration |
|---|---|---|---|---|
| `demo_db_postgres` | `.10` | Database Server | PostgreSQL (5432) | None |
| `demo_db_mysql` | `.11` | Database Server | MySQL (3306) | None |
| `demo_db_redis` | `.12` | Database Server | Redis (6379) | **No auth** — `redis-info` NSE connects unauthenticated |
| `demo_db_mongo` | `.13` | Database Server | MongoDB (27017) | None |

### Tier 2 — Network Infrastructure (172.20.0.20–.23)

| Container | IP | Profile | Services | Misconfiguration |
|---|---|---|---|---|
| `demo_router_core` | `.20` | Router | SSH(22)+Telnet(23)+SNMP(161)+BGP(179) | **SNMP community `public`** — `snmp-info` succeeds |
| `demo_firewall_edge` | `.21` | Firewall | SSH(22)+HTTPS(443)+Admin(8443) | None |
| `demo_jumpbox` | `.22` | Jump Host | SSH(22)+Bastion(2222) | None |
| `demo_ldap_server` | `.23` | Active Directory / LDAP | LDAP(389)+LDAPS(636) | **Anonymous bind** — `ldap-search` returns entries |

### Tier 3 — Services (172.20.0.30–.33)

| Container | IP | Profile | Services | Misconfiguration |
|---|---|---|---|---|
| `demo_web_frontend` | `.30` | Web Server | HTTP(80)+HTTPS(443) | None |
| `demo_app_server` | `.31` | Application Server | Tomcat(8080)+HTTPS-alt(8443) | None |
| `demo_mail_server` | `.32` | Mail Server | SMTP(25)+POP3(110)+IMAP(143)+SMTPS(465)+Submission(587)+IMAPS(993)+POP3S(995) | **Open relay** — `smtp-open-relay` NSE detects relay |
| `demo_dns_server` | `.33` | DNS Server | DNS(53)+RNDC(953) | **Zone transfer + recursion** — `dns-zone-transfer` + `dns-recursion` succeed |

### Tier 4 — Storage (172.20.0.40–.41)

| Container | IP | Profile | Services | Misconfiguration |
|---|---|---|---|---|
| `demo_nas` | `.40` | NAS Appliance | SMB(445)+rsync(873)+AFP(548)+NFS(2049)+DSM(5000+5001) | **Anonymous Samba share** — `smb-enum-shares` finds `[data]` |
| `demo_winfs` | `.41` | Windows File Server | SMB(445)+MSRPC(135)+NetBIOS(139) | **SMB signing disabled** — `smb-security-mode` reports it |

### Tier 5 — IoT Cameras (172.20.0.50–.51)

| Container | IP | Profile | Services |
|---|---|---|---|
| `demo_camera_hikvision` | `.50` | IoT Camera | RTSP(554)+Management(8000)+ONVIF(8899) |
| `demo_camera_dahua` | `.51` | IoT Camera | RTSP(554)+HTTP(80)+Dahua(37777) |

### Tier 6 — Workstations (172.20.0.60–.65)

| Container | IP | Expected Score | Notes |
|---|---|---|---|
| `demo_ws_1` | `.60` | HIGH | Hardened workstation — SMB(445)+RDP(3389) |
| `demo_ws_2` | `.61` | HIGH | Hardened workstation — SMB(445)+RDP(3389) |
| `demo_ws_3` | `.62` | HIGH | Mixed OS — SMB(445)+SSH(22) |
| `demo_ws_4` | `.63` | HIGH | SMB signing disabled banner (classification only) |
| `demo_ws_dev_1` | `.64` | HIGH | Dev workstation — SSH(22)+HTTP(3000)+HTTP(8000) |
| `demo_ws_dev_2` | `.65` | **CRITICAL NAS (intentional false positive)** | SSH(22)+HTTP(5000)+HTTP(5001) — port pair matches Synology DSM combo; documents port-only scoring limit |

### Tier 7 — Printers / Copiers (172.20.0.70–.72)

| Container | IP | Expected Score | Ports |
|---|---|---|---|
| `demo_printer_1` | `.70` | LOW | JetDirect(9100)+IPP(631) |
| `demo_printer_2` | `.71` | LOW | JetDirect(9100)+IPP(631) |
| `demo_copier` | `.72` | LOW | JetDirect(9100)+IPP(631)+HTTP(80)+SMB(445) |

### Tier 8 — Specialty Noise (172.20.0.80–.85)

| Container | IP | Identity | Expected Score |
|---|---|---|---|
| `demo_voip_1` | `.80` | VoIP phone | LOW |
| `demo_voip_2` | `.81` | VoIP phone | LOW |
| `demo_switch` | `.82` | Managed switch | Router CRITICAL (UDP scan) or HIGH (TCP-only) — non-deterministic |
| `demo_ups` | `.83` | UPS / PDU | LOW |
| `demo_videoconf` | `.84` | Video conferencing | Web Server CRITICAL — ports 80+443 score 7 points (port_exact +4, combo +3) |
| `demo_accessctrl` | `.85` | Access controller | LOW |

---

## How to Run the Demo (Ubuntu)

### Prerequisites

Run the setup script from the project root (one-time):
```bash
chmod +x setup.sh && ./setup.sh
```

### 1. Start the Lab

```bash
cd demo_lab
docker-compose up -d
```

First run downloads images — may take several minutes. The mail server container installs aiosmtpd via pip at startup (~30s). Tomcat takes ~15s to become ready.

### 2. Verify the Lab is Running

```bash
docker ps | grep demo_ | wc -l
# Should print 31
```

### 3. Run Reconesis (CLI)

```bash
source venv/bin/activate
sudo venv/bin/python main.py --target 172.20.0.0/24 --verbose
```

> `sudo` is required — Nmap needs raw socket access for SYN scans on Linux.

### 4. Run Reconesis (Dashboard)

```bash
source venv/bin/activate
sudo venv/bin/python dashboard.py
# Open http://localhost:5000
# Enter target: 172.20.0.0/24
```

### 5. Stop the Lab

```bash
cd demo_lab
docker-compose down
```

---

## Expected Reconesis Output

When pointed at `172.20.0.0/24`:

**CRITICAL** (triggers Hunter Mode):
- `.10–.13` → Database Server
- `.20` → Router
- `.21` → Firewall
- `.22` → Jump Host
- `.23` → Active Directory / LDAP
- `.30` → Web Server
- `.31` → Application Server
- `.32` → Mail Server
- `.33` → DNS Server
- `.40` → NAS Appliance
- `.41` → Windows File Server
- `.50, .51` → IoT Camera
- `.65` → NAS Appliance (intentional false positive — port 5000+5001 pair)

**HIGH / Variable** (non-deterministic):
- `.82` → Router (CRITICAL if UDP scan hits port 161, HIGH otherwise)

**HIGH**:
- `.60–.64` → Workstations (Windows File Server profile — port 445 triggers +2 points)

**LOW**:
- `.70–.72` → Printers
- `.80, .81, .83, .85` → Generic Host

---

## Output Files

After scanning, collect from the project root:
- `scan_results.json` — TOON-formatted structured scan data
- `scan_report.md` — AI-generated Markdown vulnerability report
- `reconesis.log` — Full run log with timing and depth metrics
