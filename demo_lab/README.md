# Reconesis Demo Lab — Meridian Legal LLP

Simulates the internal network of a fictional 50-person law firm. 18 containers on `recon_net` at `172.20.0.0/24`.

## Quick Start

```bash
# First time only — build the samba base image:
docker build -f Dockerfile.samba -t demo-samba:latest .
# Start:
docker-compose up -d
# Scan:
sudo venv/bin/python main.py --target 172.20.0.0/24
# Teardown:
docker-compose down
```

## Device Roster

| Container | IP | Role | Open Ports | Expected Criticality (post-LLM) |
|---|---|---|---|---|
| `dc01` | 172.20.0.10 | Active Directory Domain Controller | 53, 88, 135, 389, 445, 636, 3268 | CRITICAL |
| `casedb` | 172.20.0.11 | PostgreSQL case management database | 5432 | CRITICAL |
| `mail01` | 172.20.0.12 | Mail server (Postfix/Dovecot style) | 25, 143, 587, 993 | CRITICAL |
| `ipcam01` | 172.20.0.13 | HikVision IP security camera | 554, 8000, 8899 | CRITICAL |
| `files01` | 172.20.0.20 | Windows file server (matter docs) | 135, 139, 445 | HIGH |
| `jumpbox` | 172.20.0.21 | IT bastion host | 2222 | HIGH |
| `appserver` | 172.20.0.22 | Tomcat practice management app | 8080, 8443 | HIGH |
| `nas01` | 172.20.0.23 | NAS appliance (Synology backup) | 445, 5000, 5001 | HIGH |
| `web01` | 172.20.0.30 | Company website + client portal | 80, 443 | MEDIUM |
| `devbox` | 172.20.0.31 | Developer workstation | 22, 3000 | MEDIUM |
| `monitor01` | 172.20.0.32 | Internal monitoring dashboard | 80 | MEDIUM |
| `ws01` | 172.20.0.40 | Office workstation | none | LOW |
| `ws02` | 172.20.0.41 | Office workstation | none | LOW |
| `ws03` | 172.20.0.42 | Managed workstation (RDP) | 3389 | LOW |
| `printer01` | 172.20.0.50 | HP LaserJet printer | 9100, 631 | LOW |
| `printer02` | 172.20.0.51 | Xerox copier | 9100, 631, 80 | LOW |
| `voip01` | 172.20.0.60 | IP phone (SIP) | 5060 | LOW |
| `ups01` | 172.20.0.61 | APC UPS management card | 80 | LOW |

## Expected Results

After `docker-compose up -d`, a Reconesis scan of `172.20.0.0/24` should produce:

1. **18 hosts discovered** in Phase 1 (ICMP discovery).
2. **Post-LLM distribution**: 4 CRITICAL / 4 HIGH / 3 MEDIUM / 7 LOW.
3. **Hunter mode** targets dc01, casedb, mail01, ipcam01.
4. **Report** identifies crown jewels: AD domain controller, case management database, mail server.

**Note on static scorer vs. LLM:** The static scorer will classify ~12 devices as CRITICAL (port 80 alone scores 8, SMB triple is 15+). This is expected — the LLM classifier overrides based on device type context (printers, UPS, workstations, web/monitoring servers all get corrected to their realistic tiers). The 4C/4H/3M/7L target is post-LLM.

## Architecture Notes

- `dc01`: `alpine:3.19` with socat stubs for all AD ports (53, 88, 135, 389, 445, 636, 3268). Replaced `osixia/openldap:1.5.0` — that image is Debian Buster-based (EOL) and can no longer install packages.
- `casedb`: real PostgreSQL — nmap accurately detects service and product.
- `files01`, `nas01`: `demo-samba:latest` (Alpine + samba + socat pre-baked). Real Samba on 445/139; socat stubs for MSRPC (135), NetBIOS (139 on files01), and Synology DSM (5000/5001 on nas01). Pre-built image avoids `apk add samba` race condition on container startup.
- `jumpbox`: real OpenSSH on 2222 only.
- `appserver`: real Tomcat on 8080; socat stub with Tomcat banner on 8443.
- `devbox`: real OpenSSH on 22; socat stub (Node.js banner) on 3000.
- `web01`: nginx with self-signed cert (cert generated at container start).
- All other ports: socat stubs emitting product-string HTTP/SMTP/SIP banners. Commands use `command: [sh, -c, |...]` list form (not `command: >`) to avoid nested-quote mangling of `EXEC:'printf "..."'` arguments.
- **Build prerequisite**: run `docker build -f Dockerfile.samba -t demo-samba:latest .` once before `docker-compose up -d`.
