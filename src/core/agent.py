
import requests
import json
import logging
from src.utils.config import Config


class GroqAgent:
    def __init__(self):
        self.logger = logging.getLogger("GroqAgent")
        self.api_url = Config.GROQ_API_URL
        self.api_key = Config.GROQ_API_KEY
        self.model = Config.GROQ_MODEL

    def generate_strategy(self, context_data: dict) -> str:
        """
        Generates the next Nmap command based on the system state (Scout vs Hunter).
        Uses proper system/user message roles for stronger LLM instruction-following.
        """
        phase = context_data.get("phase", "discovery")
        target_scope = context_data.get("target_scope", "unknown")
        previous_findings = context_data.get("previous_findings", [])

        # ── OUTPUT FORMAT GUARDRAIL ────────────────────────────────────
        output_rule = (
            "\n\nCRITICAL RULES:\n"
            "1. Output ONLY a single, valid nmap command string.\n"
            "2. Do NOT wrap output in markdown code fences, backticks, or any formatting.\n"
            "3. Do NOT include explanations, comments, or notes.\n"
            "4. Example of a correct response: nmap -sS --top-ports 1000 192.168.1.0/24\n"
        )

        # ── SYSTEM PROMPTS ─────────────────────────────────────────────

        # System Prompt 1: Scout Mode (Initial Scans)
        scout_prompt = (
            "You are the 'Scout' module of Reconesis, an automated network reconnaissance engine. "
            "Your objective is broad network mapping and asset discovery. "
            "You must balance speed, stealth, and coverage. Prefer techniques that minimize "
            "network noise (e.g., SYN stealth scans, ping sweeps, ARP discovery) while maximizing "
            "host and service detection. Adapt your approach based on the target scope and context provided."
            + output_rule
        )

        # System Prompt 2: Hunter Mode — Database Servers
        hunter_db_prompt = (
            "You are the 'Hunter' module of Reconesis targeting a Database Server. "
            "Your goal is deep investigation: identify the exact database engine and version, "
            "check for authentication weaknesses, and enumerate database-specific vulnerabilities. "
            "Use version detection (-sV), OS fingerprinting (-O), and relevant NSE scripts such as "
            "mysql-info, mysql-empty-password, ms-sql-info, pgsql-brute, mongodb-info, redis-info. "
            "Select scripts appropriate for the specific database type detected."
            + output_rule
        )

        # System Prompt 3: Hunter Mode — Mail Servers
        hunter_mail_prompt = (
            "You are the 'Hunter' module of Reconesis targeting a Mail Server. "
            "Your goal is to verify mail services and check for critical misconfigurations: "
            "open relays, SMTP user enumeration, and STARTTLS support. "
            "Use version detection (-sV) and relevant NSE scripts such as "
            "smtp-open-relay, smtp-enum-users, smtp-commands, smtp-vuln-cve2010-4344, "
            "imap-capabilities, pop3-capabilities. "
            "Scan all standard mail ports: 25, 110, 143, 465, 587, 993, 995."
            + output_rule
        )

        # System Prompt 4: Hunter Mode — Routers & Firewalls
        hunter_infra_prompt = (
            "You are the 'Hunter' module of Reconesis targeting Network Infrastructure (Router/Firewall). "
            "Your goal is to fingerprint the device, identify the firmware version, and check for "
            "exposed management interfaces, default credentials, and SNMP community strings. "
            "Use OS fingerprinting (-O), version detection (-sV), and relevant NSE scripts such as "
            "banner, ssh-auth-methods, http-title, snmp-brute, snmp-info, telnet-brute."
            + output_rule
        )

        # System Prompt 5: Hunter Mode — Web/Generic
        hunter_generic_prompt = (
            "You are the 'Hunter' module of Reconesis targeting a Web Server or general host. "
            "Your goal is to identify the web technology stack, check for common web vulnerabilities, "
            "and enumerate exposed endpoints. "
            "Use version detection (-sV) and relevant NSE scripts such as "
            "http-title, http-headers, http-enum, http-methods, http-vuln-cve2017-5638, vuln."
            + output_rule
        )

        # System Prompt 6: Hunter Mode — Active Directory / LDAP
        hunter_ldap_prompt = (
            "You are the 'Hunter' module of Reconesis targeting an Active Directory / LDAP Server. "
            "Your goal is to enumerate directory services, identify exposed accounts, check for "
            "anonymous bind vulnerabilities, and identify privilege escalation vectors. "
            "Use version detection (-sV) and relevant NSE scripts such as "
            "ldap-search, ldap-brute, ldap-rootdse, msrpc-enum, smb-security-mode, "
            "krb5-enum-users (if port 88 is open), dns-srv-enum. "
            "Scan all standard LDAP ports: 389, 636, 3268, 3269, 88."
            + output_rule
        )

        # System Prompt 7: Hunter Mode — Jump Host / Bastion
        hunter_jump_prompt = (
            "You are the 'Hunter' module of Reconesis targeting a Jump Host / Bastion Server. "
            "Your goal is to identify SSH hardening posture, check for weak authentication, "
            "enumerate supported key exchange and cipher algorithms, and identify whether "
            "multi-factor authentication is enforced. "
            "Use version detection (-sV) and relevant NSE scripts such as "
            "ssh-auth-methods, ssh-hostkey, ssh2-enum-algos, banner. "
            "Scan both standard SSH (22) and non-standard bastion ports (2222, 22222)."
            + output_rule
        )

        # System Prompt 8: Hunter Mode — Web Server
        hunter_web_prompt = (
            "You are the 'Hunter' module of Reconesis targeting a Web Server. "
            "Your goal is to identify the web technology stack, enumerate directories "
            "and virtual hosts, check for common web vulnerabilities, and find exposed "
            "admin interfaces. "
            "Use version detection (-sV) and relevant NSE scripts such as "
            "http-title, http-headers, http-enum, http-methods, http-server-header, "
            "http-vuln-cve2017-5638, http-shellshock, http-robots.txt, http-git. "
            "Scan all common web ports: 80, 443, 8080, 8443, 8000, 8888."
            + output_rule
        )

        # System Prompt 9: Hunter Mode — Application Server
        hunter_app_prompt = (
            "You are the 'Hunter' module of Reconesis targeting an Application Server. "
            "Your goal is to identify the middleware platform, find exposed management "
            "consoles, check for Java deserialization vulnerabilities, and enumerate "
            "deployed applications. "
            "Use version detection (-sV) and relevant NSE scripts such as "
            "http-title, http-enum, http-auth-finder, http-default-accounts, "
            "http-vuln-cve2010-0738 (JBoss), ajp-headers, ajp-request. "
            "Scan app server ports: 8080, 8443, 4848, 9990, 7001, 7002."
            + output_rule
        )

        # System Prompt 10: Hunter Mode — IoT Camera
        hunter_iot_prompt = (
            "You are the 'Hunter' module of Reconesis targeting an IoT IP Camera. "
            "Your goal is to enumerate RTSP stream URLs, identify the camera make/model, "
            "check for default credentials on the web management interface, and detect "
            "known firmware vulnerabilities. "
            "Use version detection (-sV) and relevant NSE scripts such as "
            "rtsp-url-brute, rtsp-methods, http-default-accounts, http-auth-finder, "
            "http-title, http-methods. "
            "Scan all standard camera ports: 554 (RTSP), 1935 (RTMP), 8000, 8080, 8888 "
            "(management), 8899 (ONVIF), 37777 (Dahua)."
            + output_rule
        )

        # System Prompt 11: Hunter Mode — NAS Appliance
        hunter_nas_prompt = (
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
            + output_rule
        )

        # System Prompt 12: Hunter Mode — Windows File Server
        hunter_winfs_prompt = (
            "You are the 'Hunter' module of Reconesis targeting a Windows File Server. "
            "Your goal is to enumerate SMB shares and their permissions, verify SMB signing "
            "enforcement, check for null session access, test for EternalBlue (MS17-010) and "
            "other critical SMB vulnerabilities, and enumerate RPC endpoints. "
            "Use version detection (-sV) and relevant NSE scripts such as "
            "smb-enum-shares, smb-vuln-ms17-010, smb-security-mode, smb-os-discovery, "
            "msrpc-enum, smb-vuln-ms10-054. "
            "Scan all standard Windows file sharing ports: 135 (MSRPC), 139 (NetBIOS), "
            "445 (SMB), 3389 (RDP)."
            + output_rule
        )

        # System Prompt 13: Hunter Mode — DNS Server
        hunter_dns_prompt = (
            "You are the 'Hunter' module of Reconesis targeting a DNS Server. "
            "Your goal is to test for zone transfer (AXFR) misconfiguration, verify whether "
            "open recursion is enabled, fingerprint the resolver version via NSID, and detect "
            "DNS cache snooping vulnerabilities. "
            "Use version detection (-sV) and relevant NSE scripts such as "
            "dns-zone-transfer, dns-nsid, dns-cache-snoop, dns-recursion, dns-service-discovery. "
            "Scan all standard DNS server ports: 53 (DNS), 953 (BIND RNDC)."
            + output_rule
        )

        # ── BUILD CONTEXT ──────────────────────────────────────────────
        # Include previous findings for OODA loop context (Proposal §4.1)
        history_context = ""
        if previous_findings:
            summary = json.dumps(previous_findings, indent=2)
            history_context = (
                f"\n\nPrevious scan findings (use this context to refine your strategy):\n{summary}\n"
            )

        system_prompt = ""
        user_prompt = ""

        if phase == "discovery":
            system_prompt = scout_prompt
            user_prompt = (
                f"Target scope: {target_scope}\n"
                "Reconnaissance phase: Initial Discovery.\n"
                "Objective: Identify all live hosts on this network as quickly as possible.\n"
                "Consider the most efficient discovery technique for this target scope "
                "(e.g., ICMP echo, ARP ping, TCP SYN ping). Disable DNS resolution for speed."
                + history_context
            )

        elif phase == "port_scan":
            system_prompt = scout_prompt
            live_hosts = context_data.get("live_hosts", [])
            targets_str = " ".join(live_hosts)
            user_prompt = (
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
                "Requirements:\n"
                "- Use SYN stealth scan (-sS) with version detection (-sV)\n"
                "- Use an explicit -p flag with a port list broad enough to cover all the asset types above\n"
                "- Do NOT use --top-ports; choose specific ports with -p for predictable coverage\n"
                "- List all target IPs space-separated at the END of the command"
                + history_context
            )

        elif phase == "hunter":
            critical_targets = context_data.get("critical_targets", [])

            # ── MIXED ASSET TYPE HANDLING ──────────────────────────────
            # Group targets by type and select the best prompt for the majority,
            # but combine all target IPs into one command for efficiency.
            types_present = {t.get("type", "").lower() for t in critical_targets}

            if any(k in t for t in types_present for k in ["database", "db"]):
                system_prompt = hunter_db_prompt
            elif any(k in t for t in types_present for k in ["mail"]):
                system_prompt = hunter_mail_prompt
            elif any(k in t for t in types_present for k in ["router", "firewall"]):
                system_prompt = hunter_infra_prompt
            elif any(k in t for t in types_present for k in ["active directory", "ldap"]):
                system_prompt = hunter_ldap_prompt
            elif any(k in t for t in types_present for k in ["jump host"]):
                system_prompt = hunter_jump_prompt
            elif any(k in t for t in types_present for k in ["application server"]):
                system_prompt = hunter_app_prompt
            elif any(k in t for t in types_present for k in ["web server"]):
                system_prompt = hunter_web_prompt
            elif any(k in t for t in types_present for k in ["iot camera", "camera"]):
                system_prompt = hunter_iot_prompt
            else:
                system_prompt = hunter_generic_prompt

            details = "\n".join([f"- {t['ip']} (classified as: {t['type']})" for t in critical_targets])
            user_prompt = (
                f"Critical assets requiring deep investigation:\n{details}\n\n"
                "Reconnaissance phase: Hunter Mode — Deep Scan.\n"
                "Objective: Run targeted vulnerability checks and version enumeration "
                "against these specific high-value targets. "
                "Generate a single comprehensive Nmap command covering all listed targets."
                + history_context
            )

        result, _ = self._query_groq(system_prompt, user_prompt)
        return result

    def analyze_results(self, toon_data: list) -> str:
        """
        Analyzes the final TOON data to produce a summary report.
        Uses a longer timeout and explicit token cap for multi-page reports.
        If the model hits the token limit, makes one continuation call to complete the report.
        """
        system_prompt, user_prompt = self._build_analysis_prompt(toon_data)
        report, finish_reason = self._query_groq(
            system_prompt, user_prompt, timeout=120, max_tokens=4096
        )

        if finish_reason == "length" and report:
            self.logger.warning(
                "Report was truncated (finish_reason=length). Requesting continuation..."
            )
            continuation_system = (
                "You are a Senior Cybersecurity Analyst. "
                "The report below was cut off due to length. "
                "Continue writing from exactly where it stopped. "
                "Do not repeat any content that has already been written. "
                "Complete all remaining sections: "
                "# Recommended Remediation Actions and # Conclusion."
            )
            continuation_user = (
                f"The report so far:\n\n{report}\n\n"
                "Continue from where the report was cut off."
            )
            continuation, _ = self._query_groq(
                continuation_system, continuation_user, timeout=120, max_tokens=2048
            )
            if continuation:
                report = report + "\n" + continuation

        return report

    def _query_groq(self, system_prompt: str, user_prompt: str,
                    timeout: int = 30, max_tokens: int = None) -> tuple:
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
        try:
            response = requests.post(self.api_url, headers=headers, json=payload, timeout=timeout)
            response.raise_for_status()
            data = response.json()
            choice = data["choices"][0]
            # Strip markdown code fences if the LLM wraps output
            result = choice["message"]["content"].strip()
            result = result.replace("```", "").replace("`", "").strip()
            finish_reason = choice.get("finish_reason", "stop")
            return result, finish_reason
        except requests.exceptions.HTTPError as e:
            status_code = e.response.status_code if e.response else "unknown"
            self.logger.error(f"Groq API HTTP error ({status_code}): {e}")
            if e.response is not None:
                self.logger.error(f"Response body: {e.response.text[:500]}")
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
            "Active Directory/LDAP, Jump Hosts, Web Servers, Application Servers) "
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
