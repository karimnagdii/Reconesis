
import re
import time
import requests
import json
import logging
from src.utils.config import Config


class GroqAgent:
    _OUTPUT_RULE = (
        "\n\nCRITICAL RULES:\n"
        "1. Output ONLY a single, valid nmap command string.\n"
        "2. Do NOT wrap output in markdown code fences, backticks, or any formatting.\n"
        "3. Do NOT include explanations, comments, or notes.\n"
        "4. Example of a correct response: nmap -sS --top-ports 1000 192.168.1.0/24\n"
    )

    _SYSTEM_PROMPTS = {
        "scout": (
            "You are the 'Scout' module of Reconesis, an automated network reconnaissance engine. "
            "Your objective is broad network mapping and asset discovery. "
            "You must balance speed, stealth, and coverage. Prefer techniques that minimize "
            "network noise (e.g., SYN stealth scans, ping sweeps, ARP discovery) while maximizing "
            "host and service detection. Adapt your approach based on the target scope and context provided."
            + _OUTPUT_RULE
        ),
        "hunter_database": (
            "You are the 'Hunter' module of Reconesis targeting a Database Server. "
            "Your goal is deep investigation: identify the exact database engine and version, "
            "check for authentication weaknesses, and enumerate database-specific vulnerabilities. "
            "Use version detection (-sV), OS fingerprinting (-O), and relevant NSE scripts such as "
            "mysql-info, mysql-empty-password, ms-sql-info, pgsql-brute, mongodb-info, redis-info. "
            "Select scripts appropriate for the specific database type detected."
            + _OUTPUT_RULE
        ),
        "hunter_mail": (
            "You are the 'Hunter' module of Reconesis targeting a Mail Server. "
            "Your goal is to verify mail services and check for critical misconfigurations: "
            "open relays, SMTP user enumeration, and STARTTLS support. "
            "Use version detection (-sV) and relevant NSE scripts such as "
            "smtp-open-relay, smtp-enum-users, smtp-commands, smtp-vuln-cve2010-4344, "
            "imap-capabilities, pop3-capabilities. "
            "Scan all standard mail ports: 25, 110, 143, 465, 587, 993, 995."
            + _OUTPUT_RULE
        ),
        "hunter_infra": (
            "You are the 'Hunter' module of Reconesis targeting Network Infrastructure (Router/Firewall). "
            "Your goal is to fingerprint the device, identify the firmware version, and check for "
            "exposed management interfaces, default credentials, and SNMP community strings. "
            "Use OS fingerprinting (-O), version detection (-sV), and relevant NSE scripts such as "
            "banner, ssh-auth-methods, http-title, snmp-brute, snmp-info, telnet-brute."
            + _OUTPUT_RULE
        ),
        "hunter_ldap": (
            "You are the 'Hunter' module of Reconesis targeting an Active Directory / LDAP Server. "
            "Your goal is to enumerate directory services, identify exposed accounts, check for "
            "anonymous bind vulnerabilities, and identify privilege escalation vectors. "
            "Use version detection (-sV) and relevant NSE scripts such as "
            "ldap-search, ldap-brute, ldap-rootdse, msrpc-enum, smb-security-mode, "
            "krb5-enum-users (if port 88 is open), dns-srv-enum. "
            "Scan all standard LDAP ports: 389, 636, 3268, 3269, 88."
            + _OUTPUT_RULE
        ),
        "hunter_jump": (
            "You are the 'Hunter' module of Reconesis targeting a Jump Host / Bastion Server. "
            "Your goal is to identify SSH hardening posture, check for weak authentication, "
            "enumerate supported key exchange and cipher algorithms, and identify whether "
            "multi-factor authentication is enforced. "
            "Use version detection (-sV) and relevant NSE scripts such as "
            "ssh-auth-methods, ssh-hostkey, ssh2-enum-algos, banner. "
            "Scan both standard SSH (22) and non-standard bastion ports (2222, 22222)."
            + _OUTPUT_RULE
        ),
        "hunter_app": (
            "You are the 'Hunter' module of Reconesis targeting an Application Server. "
            "Your goal is to identify the middleware platform, find exposed management "
            "consoles, check for Java deserialization vulnerabilities, and enumerate "
            "deployed applications. "
            "Use version detection (-sV) and relevant NSE scripts such as "
            "http-title, http-enum, http-auth-finder, http-default-accounts, "
            "http-vuln-cve2010-0738 (JBoss), ajp-headers, ajp-request. "
            "Scan app server ports: 8080, 8443, 4848, 9990, 7001, 7002."
            + _OUTPUT_RULE
        ),
        "hunter_web": (
            "You are the 'Hunter' module of Reconesis targeting a Web Server. "
            "Your goal is to identify the web technology stack, enumerate directories "
            "and virtual hosts, check for common web vulnerabilities, and find exposed "
            "admin interfaces. "
            "Use version detection (-sV) and relevant NSE scripts such as "
            "http-title, http-headers, http-enum, http-methods, http-server-header, "
            "http-vuln-cve2017-5638, http-shellshock, http-robots.txt, http-git. "
            "Scan all common web ports: 80, 443, 8080, 8443, 8000, 8888."
            + _OUTPUT_RULE
        ),
        "hunter_iot": (
            "You are the 'Hunter' module of Reconesis targeting an IoT IP Camera. "
            "Your goal is to enumerate RTSP stream URLs, identify the camera make/model, "
            "check for default credentials on the web management interface, and detect "
            "known firmware vulnerabilities. "
            "Use version detection (-sV) and relevant NSE scripts such as "
            "rtsp-url-brute, rtsp-methods, http-default-accounts, http-auth-finder, "
            "http-title, http-methods. "
            "Scan all standard camera ports: 554 (RTSP), 1935 (RTMP), 8000, 8080, 8888 "
            "(management), 8899 (ONVIF), 37777 (Dahua)."
            + _OUTPUT_RULE
        ),
        "hunter_nas": (
            "You are the 'Hunter' module of Reconesis targeting a NAS Appliance. "
            "Your goal is to enumerate file shares, check for default credentials on the web "
            "management interface, test for anonymous NFS and SMB access, and detect known "
            "firmware vulnerabilities (including QNAP QLocker/DeadBolt and Synology CVEs). "
            "SMB enumeration is included because NAS devices universally offer SMB shares "
            "alongside NFS and AFP. "
            "Use version detection (-sV) and relevant NSE scripts such as "
            "smb-enum-shares, smb-security-mode, nfs-ls, nfs-showmount, ftp-anon, "
            "http-default-accounts, http-auth-finder, http-title. "
            "Scan all standard NAS ports: 21 (FTP), 22 (SSH), 80, 139, 443, 445 (SMB), "
            "548 (AFP), 873 (rsync), 2049 (NFS), 3260 (iSCSI), 5000, 5001 (Synology DSM), "
            "8080 (QNAP)."
            + _OUTPUT_RULE
        ),
        "hunter_winfs": (
            "You are the 'Hunter' module of Reconesis targeting a Windows File Server. "
            "Your goal is to enumerate SMB shares and their permissions, verify SMB signing "
            "enforcement, check for null session access, test for EternalBlue (MS17-010) and "
            "other critical SMB vulnerabilities, and enumerate RPC endpoints. "
            "Use version detection (-sV) and relevant NSE scripts such as "
            "smb-enum-shares, smb-vuln-ms17-010, smb-security-mode, smb-os-discovery, "
            "msrpc-enum, smb-vuln-ms10-054. "
            "Scan all standard Windows file sharing ports: 135 (MSRPC), 139 (NetBIOS), "
            "445 (SMB), 3389 (RDP)."
            + _OUTPUT_RULE
        ),
        "hunter_dns": (
            "You are the 'Hunter' module of Reconesis targeting a DNS Server. "
            "Your goal is to test for zone transfer (AXFR) misconfiguration, verify whether "
            "open recursion is enabled, fingerprint the resolver version via NSID, and detect "
            "DNS cache snooping vulnerabilities. "
            "Use version detection (-sV) and relevant NSE scripts such as "
            "dns-zone-transfer, dns-nsid, dns-cache-snoop, dns-recursion, dns-service-discovery. "
            "Scan all standard DNS server ports: 53 (DNS), 953 (BIND RNDC)."
            + _OUTPUT_RULE
        ),
        "hunter_generic": (
            "You are the 'Hunter' module of Reconesis targeting a Web Server or general host. "
            "Your goal is to identify the web technology stack, check for common web vulnerabilities, "
            "and enumerate exposed endpoints. "
            "Use version detection (-sV) and relevant NSE scripts such as "
            "http-title, http-headers, http-enum, http-methods, http-vuln-cve2017-5638, vuln."
            + _OUTPUT_RULE
        ),
    }

    _CLASSIFY_SYSTEM_PROMPT = (
        "You are a network asset classifier for a penetration testing tool.\n"
        "You will receive a JSON array of hosts. Each host includes open ports,\n"
        "service data, OS fingerprints, NSE script output, and a static scoring\n"
        "breakdown.\n\n"
        "Classify each host with:\n"
        "- type: one of [Database Server, Mail Server, Firewall, Router,\n"
        "  Active Directory / LDAP, Jump Host, Web Server, Application Server,\n"
        "  IoT Camera, NAS Appliance, Windows File Server, DNS Server, Generic Host]\n"
        "- criticality: CRITICAL | HIGH | MEDIUM | LOW\n"
        "- reasoning: one sentence explaining the key signal that decided it\n\n"
        "Classification rules:\n"
        "- Trust service data, NSE script output, and product strings over port numbers alone\n"
        "- A device with port 80 is NOT automatically a Web Server -- check product and script output\n"
        "- CRITICAL = directly exploitable core infrastructure (databases, AD, firewalls,\n"
        "  routers, mail servers, DNS, IoT cameras with default creds)\n"
        "- HIGH = significant attack surface but not core infrastructure\n"
        "  (file servers, jump hosts, application servers, workstations with SMB)\n"
        "- MEDIUM = limited exposure, non-critical services\n"
        "- LOW = printers, UPS/PDU, VoIP phones, access controllers, generic noise\n"
        "- When the static scorer fires on a single common port (80, 443, 445) with no\n"
        "  corroborating product string or NSE evidence, treat it with skepticism\n"
        "- Return ONLY a valid JSON array. No prose, no markdown, no code fences."
    )

    _REPORT_SECTION1_SYSTEM = (
        "You are a Senior Cybersecurity Analyst reviewing automated network reconnaissance results.\n"
        "Write the FIRST HALF of a professional report in Markdown. Use formal technical English. No emoji.\n\n"
        "Write ONLY these two sections — nothing else:\n\n"
        "# Executive Summary\n"
        "Brief overview of the scan scope, methodology, and key findings (3-5 sentences).\n\n"
        "# Critical Assets Identified\n"
        "A Markdown table of all CRITICAL and HIGH assets with columns: "
        "IP Address | Asset Type | Open Ports | Risk Level\n\n"
        "Stop after the table. Do NOT write Risk Assessment, Remediation, or Conclusion."
    )

    _REPORT_SECTION2_SYSTEM = (
        "You are a Senior Cybersecurity Analyst reviewing automated network reconnaissance results.\n"
        "Write the SECOND HALF of a professional report in Markdown. Use formal technical English. No emoji.\n\n"
        "Write ONLY these two sections — nothing else:\n\n"
        "# Risk Assessment\n"
        "Per-asset risk analysis for each CRITICAL and HIGH host. "
        "If 'exploits' data is present for any port, include a CVE table with columns: "
        "CVE ID | CVSS Score | Affected Service | Source. "
        "Highlight CVEs with CVSS >= 7.0 as HIGH or CRITICAL severity.\n\n"
        "# Recommended Remediation Actions\n"
        "Prioritized, actionable steps to mitigate identified risks. Reference specific CVE IDs where applicable.\n\n"
        "Do NOT repeat the executive summary or asset inventory table."
    )

    def __init__(self):
        self.logger = logging.getLogger("GroqAgent")
        self.api_url = Config.GROQ_API_URL
        self.api_key = Config.GROQ_API_KEY
        self.model = Config.GROQ_MODEL

    def _build_history_context(self, previous_findings: list) -> str:
        """Build the history context string for LLM prompts. Caps to last 2 depths."""
        if not previous_findings:
            return ""
        recent = previous_findings[-2:] if len(previous_findings) > 2 else previous_findings
        summary = json.dumps(recent, indent=2)
        return f"\n\nPrevious scan findings (depth {len(previous_findings)}, showing last 2):\n{summary}\n"

    def _select_system_prompt(self, phase: str, types_present: set) -> str:
        """Select the appropriate system prompt for the given phase and asset types.
        Returns scout prompt for discovery/port_scan. For hunter, selects by asset type priority."""
        if phase in ("discovery", "port_scan"):
            return self._SYSTEM_PROMPTS["scout"]

        # Hunter phase — select by asset type priority
        if any(k in t for t in types_present for k in ["database", "db"]):
            return self._SYSTEM_PROMPTS["hunter_database"]
        if any(k in t for t in types_present for k in ["mail"]):
            return self._SYSTEM_PROMPTS["hunter_mail"]
        if any(k in t for t in types_present for k in ["router", "firewall"]):
            return self._SYSTEM_PROMPTS["hunter_infra"]
        if any(k in t for t in types_present for k in ["active directory", "ldap"]):
            return self._SYSTEM_PROMPTS["hunter_ldap"]
        if any(k in t for t in types_present for k in ["jump host"]):
            return self._SYSTEM_PROMPTS["hunter_jump"]
        if any(k in t for t in types_present for k in ["application server"]):
            return self._SYSTEM_PROMPTS["hunter_app"]
        if any(k in t for t in types_present for k in ["web server"]):
            return self._SYSTEM_PROMPTS["hunter_web"]
        if any(k in t for t in types_present for k in ["iot camera", "camera"]):
            return self._SYSTEM_PROMPTS["hunter_iot"]
        if any(k in t for t in types_present for k in ["nas appliance"]):
            return self._SYSTEM_PROMPTS["hunter_nas"]
        if any(k in t for t in types_present for k in ["windows file server"]):
            return self._SYSTEM_PROMPTS["hunter_winfs"]
        if any(k in t for t in types_present for k in ["dns server"]):
            return self._SYSTEM_PROMPTS["hunter_dns"]
        return self._SYSTEM_PROMPTS["hunter_generic"]

    def _build_user_prompt(self, phase: str, context_data: dict, history_context: str) -> str:
        """Build the user-facing prompt for the given phase."""
        target_scope = context_data.get("target_scope", "unknown")

        if phase == "discovery":
            return (
                f"Target scope: {target_scope}\n"
                "Reconnaissance phase: Initial Discovery.\n"
                "Objective: Identify all live hosts on this network as quickly as possible.\n"
                "Consider the most efficient discovery technique for this target scope "
                "(e.g., ICMP echo, ARP ping, TCP SYN ping). Disable DNS resolution for speed."
                + history_context
            )

        if phase == "port_scan":
            live_hosts = context_data.get("live_hosts", [])
            targets_str = " ".join(live_hosts)
            return (
                f"Targets (live hosts): {targets_str}\n"
                "Reconnaissance phase: Port Scan & Service Detection.\n"
                "Objective: Identify open ports and running services on these hosts to classify them as:\n"
                "  - Database servers (MySQL/3306, PostgreSQL/5432, MongoDB/27017, Redis/6379, MSSQL/1433, Oracle/1521)\n"
                "  - Mail servers (SMTP/25, IMAP/143, POP3/110, Submission/587)\n"
                "  - Network infrastructure: routers (SSH/22+Telnet/23+BGP/179), firewalls (SSH/22+HTTPS/443+8443)\n"
                "  - Active Directory / LDAP servers (LDAP/389, LDAPS/636, Global Catalog/3268-3269, Kerberos/88)\n"
                "  - Jump Hosts / Bastion servers (non-standard SSH on port 2222 or 22222)\n"
                "  - Web servers (HTTP/80, HTTPS/443, HTTP-alt/8080, 8443)\n"
                "  - Application servers (Tomcat/JBoss/WildFly on 8080, 8443, 4848, 9990, 7001, 7002)\n"
                "  - IoT Cameras (RTSP/554, RTMP/1935, ONVIF/8899, HikVision/8000, Dahua/37777)\n"
                "  - NAS Appliances (AFP/548, NFS/2049, iSCSI/3260, rsync/873, Synology DSM/5000-5001, QNAP/8080)\n"
                "  - Windows File Servers (SMB/445, NetBIOS/139, MSRPC/135)\n"
                "  - DNS Servers (DNS/53, BIND RNDC/953)\n"
                "Requirements:\n"
                "- Use SYN stealth scan (-sS) with version detection (-sV)\n"
                "- Use an explicit -p flag with a port list broad enough to cover all the asset types above\n"
                "- Do NOT use --top-ports; choose specific ports with -p for predictable coverage\n"
                "- List all target IPs space-separated at the END of the command"
                + history_context
            )

        # hunter phase
        critical_targets = context_data.get("critical_targets", [])
        details = "\n".join([f"- {t['ip']} (classified as: {t['type']})" for t in critical_targets])
        return (
            f"Critical assets requiring deep investigation:\n{details}\n\n"
            "Reconnaissance phase: Hunter Mode — Deep Scan.\n"
            "Objective: Run targeted vulnerability checks and version enumeration "
            "against these specific high-value targets. "
            "Generate a single comprehensive Nmap command covering all listed targets."
            + history_context
        )

    def generate_strategy(self, context_data: dict) -> str:
        """
        Generates the next Nmap command based on the system state (Scout vs Hunter).
        Uses proper system/user message roles for stronger LLM instruction-following.
        """
        phase = context_data.get("phase", "discovery")
        previous_findings = context_data.get("previous_findings", [])
        critical_targets = context_data.get("critical_targets", [])
        types_present = {t.get("type", "").lower() for t in critical_targets}

        history_context = self._build_history_context(previous_findings)
        system_prompt = self._select_system_prompt(phase, types_present)
        user_prompt = self._build_user_prompt(phase, context_data, history_context)

        result, _ = self._query_groq(system_prompt, user_prompt)
        return result

    def classify_hosts(self, evidence_bundles: list) -> list:
        """
        Classify all hosts in one batched LLM call.
        Returns list of {ip, type, criticality, reasoning} dicts.
        Returns [] on any failure — caller falls back to static labels.
        """
        if not evidence_bundles:
            return []

        user_prompt = json.dumps(evidence_bundles, separators=(',', ':'))
        try:
            result, finish_reason = self._query_groq(
                self._CLASSIFY_SYSTEM_PROMPT,
                user_prompt,
                timeout=120,
                max_tokens=4096,
                temperature=0,
            )
            if not result or finish_reason == "error":
                self.logger.warning("classify_hosts: empty or error response from Groq")
                return []
            return json.loads(result)
        except Exception as e:
            self.logger.warning(f"classify_hosts failed: {e}")
            return []

    def analyze_results(self, toon_data: list) -> str:
        """
        Generates the final report in two targeted API calls.
        Call 1: Executive Summary + Critical Assets table.
        Call 2: Risk Assessment + Remediation.
        Falls back to the original single-call approach if either call fails.
        """
        slim_data = self._slim_toon(toon_data)
        user_prompt = (
            "Below is the complete scan data in TOON (Target-Oriented Object Notation) format. "
            "Analyze every host, paying special attention to assets classified as Critical or High.\n\n"
            f"SCAN DATA:\n{json.dumps(slim_data, indent=2)}"
        )

        try:
            section1, reason1 = self._query_groq(
                self._REPORT_SECTION1_SYSTEM, user_prompt, timeout=120, max_tokens=4096,
                strip_backticks=False
            )
            if not section1 or reason1 == "error":
                raise ValueError("Section 1 call failed")

            section2, reason2 = self._query_groq(
                self._REPORT_SECTION2_SYSTEM, user_prompt, timeout=120, max_tokens=4096,
                strip_backticks=False
            )
            if not section2 or reason2 == "error":
                raise ValueError("Section 2 call failed")

            return section1 + "\n\n---\n\n" + section2

        except Exception as e:
            self.logger.warning(f"Two-section report failed ({e}), falling back to single-call")
            system_prompt, fallback_user = self._build_analysis_prompt(toon_data)
            report, finish_reason = self._query_groq(
                system_prompt, fallback_user, timeout=120, max_tokens=4096,
                strip_backticks=False
            )

            if finish_reason == "length" and report:
                self.logger.warning("Fallback report truncated — requesting continuation")
                continuation_system = (
                    "You are a Senior Cybersecurity Analyst. "
                    "The report below was cut off. Continue from exactly where it stopped. "
                    "Do not repeat content already written. "
                    "Complete remaining sections: # Recommended Remediation Actions and # Conclusion."
                )
                continuation_user = f"The report so far:\n\n{report}\n\nContinue from where the report was cut off."
                continuation, _ = self._query_groq(
                    continuation_system, continuation_user, timeout=120, max_tokens=2048,
                    strip_backticks=False
                )
                if continuation:
                    report = report + "\n" + continuation

            return report

    def _query_groq(self, system_prompt: str, user_prompt: str,
                    timeout: int = 30, max_tokens: int = None,
                    temperature: float = None, strip_backticks: bool = True) -> tuple:
        """
        Sends a request to the Groq API using proper system/user message roles
        for stronger instruction-following.
        Returns (content, finish_reason) tuple.
        """
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            "stream": False
        }
        if max_tokens is not None:
            payload["max_tokens"] = max_tokens
        if temperature is not None:
            payload["temperature"] = temperature
        try:
            response = requests.post(self.api_url, headers=headers, json=payload, timeout=timeout)
            response.raise_for_status()
            data = response.json()
            choice = data["choices"][0]
            result = choice["message"]["content"].strip()
            if strip_backticks:
                result = result.replace("```", "").replace("`", "").strip()
            finish_reason = choice.get("finish_reason", "stop")
            return result, finish_reason
        except requests.exceptions.HTTPError as e:
            status_code = e.response.status_code if e.response else "unknown"
            self.logger.error(f"Groq API HTTP error ({status_code}): {e}")
            if e.response is not None:
                body = e.response.text[:500]
                self.logger.error(f"Response body: {body}")
                if status_code == 429:
                    # Parse suggested wait time from error body (e.g. "try again in 26.6s")
                    match = re.search(r"try again in (\d+\.?\d*)s", body)
                    wait = float(match.group(1)) + 1 if match else 30
                    self.logger.warning(f"Rate limited — waiting {wait:.1f}s then retrying once")
                    time.sleep(wait)
                    try:
                        response = requests.post(self.api_url, headers=headers, json=payload, timeout=timeout)
                        response.raise_for_status()
                        data = response.json()
                        choice = data["choices"][0]
                        result = choice["message"]["content"].strip()
                        if strip_backticks:
                            result = result.replace("```", "").replace("`", "").strip()
                        return result, choice.get("finish_reason", "stop")
                    except Exception as retry_err:
                        self.logger.error(f"Retry after rate limit also failed: {retry_err}")
                        return "", "error"
                if status_code == 401:
                    self.logger.error("API authentication failed — check your GROQ_API_KEY")
            return "", "error"
        except requests.exceptions.Timeout:
            self.logger.error(f"Groq API request timed out after {timeout} seconds")
            return "", "error"
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Groq API connection error: {e}")
            return "", "error"
        except (KeyError, ValueError) as e:
            self.logger.error(f"Failed to parse Groq API response: {e}")
            return "", "error"

    @staticmethod
    def _slim_toon(toon_data: list) -> list:
        """
        Reduces TOON payload size before sending to Groq to avoid 413 token limit errors.

        Strategy:
        - Strip raw NSE `scripts` output from all ports (already parsed into `exploits`)
        - LOW/MEDIUM hosts: keep only target, type, criticality, and minimal port list
        - CRITICAL/HIGH hosts: keep full detail but cap exploits to top 5 by CVSS score
        """
        slimmed = []
        for host in toon_data:
            level = host.get("criticality", "LOW")
            if level in ("CRITICAL", "HIGH"):
                slim_ports = []
                for p in host.get("ports", []):
                    slim_p = {k: v for k, v in p.items() if k != "scripts"}
                    # Cap exploits to top 5 by CVSS
                    if slim_p.get("exploits"):
                        slim_p["exploits"] = sorted(
                            slim_p["exploits"],
                            key=lambda e: e.get("cvss", 0),
                            reverse=True
                        )[:5]
                    slim_ports.append(slim_p)
                slimmed.append({
                    "target": host.get("target"),
                    "type": host.get("type", "Unknown"),
                    "criticality": level,
                    "os": host.get("os", {}),
                    "ports": slim_ports,
                })
            else:
                # LOW/MEDIUM: just enough context to mention in topology overview
                slimmed.append({
                    "target": host.get("target"),
                    "type": host.get("type", "Generic Host"),
                    "criticality": level,
                    "ports": [
                        {"port": p["port"], "service": p.get("service", "")}
                        for p in host.get("ports", [])
                    ],
                })
        return slimmed

    def _build_analysis_prompt(self, toon_data: list) -> tuple:
        """
        Builds a structured analysis prompt with enforced report sections.
        Returns (system_prompt, user_prompt) tuple.
        """
        system_prompt = (
            "You are a Senior Cybersecurity Analyst reviewing the results of an automated "
            "network reconnaissance scan performed by the Reconesis engine. "
            "Write a professional Final Report in Markdown format.\n\n"
            "FORMATTING AND TONE RULES — follow these exactly:\n"
            "1. Use formal, technical English. No casual language.\n"
            "2. Do NOT use emoji characters anywhere in the report — "
            "not in headings, bullet points, tables, or body text.\n"
            "3. Use plain numbered or bulleted lists for all enumerations.\n"
            "4. You MUST complete ALL sections listed below, even if a section has "
            "only brief content. Do not omit any section.\n\n"
            "You MUST structure the report with these exact sections:\n\n"
            "# Executive Summary\n"
            "A brief overview of the scan scope, methodology, and key findings.\n\n"
            "# Network Topology Overview\n"
            "A summary of discovered hosts and their roles on the network.\n\n"
            "# Critical Assets Identified\n"
            "A table of critical infrastructure found (Databases, Mail Servers, Routers, Firewalls, "
            "Active Directory/LDAP, Jump Hosts, Web Servers, Application Servers, IoT Cameras, "
            "NAS Appliances, Windows File Servers, DNS Servers) "
            "with their IP, type, open ports, and risk level.\n\n"
            "# Risk Assessment\n"
            "Per-asset risk analysis with specific vulnerability details and potential impact. "
            "For each asset, if 'exploits' data is present in any port, include a CVE table with "
            "columns: CVE ID | CVSS Score | Affected Service | Source. "
            "Highlight any CVE with CVSS >= 7.0 as HIGH or CRITICAL severity.\n\n"
            "# Recommended Remediation Actions\n"
            "Prioritized, actionable steps to mitigate the identified risks. "
            "Reference specific CVE IDs where applicable.\n\n"
            "# Conclusion\n"
            "Final summary and overall risk posture assessment."
        )

        slim_data = self._slim_toon(toon_data)
        user_prompt = (
            "Below is the complete scan data in TOON (Target-Oriented Object Notation) format. "
            "Analyze every host, paying special attention to assets classified as Critical or High. "
            "Identify patterns, exposed services, and potential attack vectors.\n\n"
            f"SCAN DATA:\n{json.dumps(slim_data, indent=2)}"
        )

        return system_prompt, user_prompt
