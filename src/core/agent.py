
import re
import time
import requests
import json
import logging
from src.utils.config import Config
from src.utils.toon_dialect import ToonDialect
from src.utils.exceptions import ReconesisAPIError, ReconesisParseError

_DIALECT_RING = (
    "SCAN DATA is in compressed dialect:\n"
    "Line 1: <IP> <T> <C> <OS>   (fields: IP, Type, Criticality, OS-if-known)\n"
    " M: <TopT>:<score>><RunnerT>:<score>   (classify only — Type aliases; static scorer guess)\n"
    "   > separates top-scoring type from runner-up type on the M: line\n"
    " <port>[u][*] <svc> <prod>/<ver> [<yr-id>:<cvss>:<src>]\n"
    "T: D=Database M=Mail R=Router F=Firewall A=AD/LDAP J=Jump W=Web\n"
    "   S=AppServer I=IoT N=NAS X=WinFS Z=DNS G=Generic\n"
    "C: C=CRITICAL H=HIGH M=MEDIUM L=LOW | ?=unk  !=noscript\n"
    "*=auth required  u=udp (default tcp)  src: n=nvd v=vulners c=circl\n"
    "M: line values are Type aliases only (never Criticality).\n\n"
)

_OUTPUT_RULE = (
    "\n\nCRITICAL RULES:\n"
    "1. Output ONLY a single, valid nmap command string.\n"
    "2. Do NOT wrap output in markdown code fences, backticks, or any formatting.\n"
    "3. Do NOT include explanations, comments, or notes.\n"
    "4. Example of a correct response: nmap -sS --top-ports 1000 192.168.1.0/24\n"
)

# Maps lowercased type substrings to hunter prompt keys (H-1: replaces 11-branch if/elif)
_TYPE_PROMPT_MAP: dict[str, str] = {
    "database":            "hunter_database",
    "db":                  "hunter_database",
    "mail":                "hunter_mail",
    "router":              "hunter_infra",
    "firewall":            "hunter_infra",
    "active directory":    "hunter_ldap",
    "ldap":                "hunter_ldap",
    "jump host":           "hunter_jump",
    "application server":  "hunter_app",
    "web server":          "hunter_web",
    "iot camera":          "hunter_iot",
    "camera":              "hunter_iot",
    "nas appliance":       "hunter_nas",
    "windows file server": "hunter_winfs",
    "dns server":          "hunter_dns",
}


def _build_hunter_prompt(asset_type: str, verb: str, nse_scripts: str) -> str:
    """Factory for hunter system prompts (H-4: replaces 12 copy-pasted strings).
    Applies _DIALECT_RING consistently to all hunter prompts."""
    return (
        _DIALECT_RING
        + f"You are the 'Hunter' module of Reconesis targeting a {asset_type}. "
        + f"Your goal is to {verb}. "
        + f"Use version detection (-sV) and relevant NSE scripts such as {nse_scripts}."
        + _OUTPUT_RULE
    )


DECIDE_SYSTEM_PROMPT = (
    _DIALECT_RING
    + "?=unk (field unknown) !=noscript (NSE output missing)\n\n"
    "You are an autonomous network recon agent. You are given:\n"
    "1. All discovered hosts in TOON with ? and ! gap markers.\n"
    "2. Scan history (last 2 depths).\n\n"
    "Generate ONE nmap command that fills the most gaps.\n\n"
    "Reply ONLY with valid JSON — no prose, no code fences:\n"
    '{\n  "command": "<nmap string>",\n'
    '  "rationale": "<one sentence>",\n'
    '  "continue": <true|false>,\n'
    '  "new_targets": ["<ip or cidr>", ...]\n}\n\n'
    "Rules:\n"
    '"continue": false only when no further scanning will yield new info.\n'
    '"new_targets": [] if no new scope hints found.'
)


DEPTH1_SYSTEM_PROMPT = (
    _DIALECT_RING
    + "You are the network mapping module of Reconesis. "
    "Your goal is to build a complete picture of the network across multiple scan iterations. "
    "Discover all device roles, identify additional subnets, detect firewall presence, "
    "and map the full attack surface. Vary your port sets and scan techniques between "
    "sub-iterations to reveal hosts that earlier scans missed. "
    "Choose ports that would expose the specific device types you are looking for: "
    "Routers, Firewalls, IoT Cameras, Active Directory/LDAP, Database Servers, "
    "Mail Servers, DNS Servers, NAS Appliances, Windows File Servers, Jump Hosts, "
    "Web Servers, Application Servers. "
    "Do NOT use -p- or --top-ports. Select explicit port lists with -p.\n\n"
    "Reply ONLY with valid JSON — no prose, no code fences:\n"
    '{\n  "command": "<nmap string>",\n'
    '  "rationale": "<one sentence>",\n'
    '  "continue": <true|false>,\n'
    '  "new_targets": ["<ip or cidr>", ...]\n}\n\n'
    '"continue": false only when you have a complete network picture.\n'
    '"new_targets": [] if no new scope hints found.'
)

DEPTH2_SYSTEM_PROMPT = (
    _DIALECT_RING
    + "You are the deep fingerprint module of Reconesis. "
    "You have a classified network map. The hosts provided are confirmed CRITICAL or HIGH assets. "
    "Go deeper — enumerate exact service versions, identify exposed management interfaces, "
    "and check for service-specific misconfigurations. "
    "Choose ports meaningful to each host's classified type. "
    "Use passive NSE scripts only: mysql-info, ldap-rootdse, smtp-commands, http-title, "
    "ssh-auth-methods, snmp-info, smb-security-mode, http-enum, ftp-anon, nfs-showmount, "
    "http-default-accounts, http-auth-finder, dns-zone-transfer, dns-recursion. "
    "Do NOT use any brute-force scripts (*-brute, *-enum-users).\n\n"
    "Reply ONLY with valid JSON — no prose, no code fences:\n"
    '{\n  "command": "<nmap string>",\n'
    '  "rationale": "<one sentence>",\n'
    '  "continue": <true|false>,\n'
    '  "new_targets": ["<ip or cidr>", ...]\n}\n\n'
    '"continue": false when no further depth-2 enumeration will yield new service data.\n'
    '"new_targets": [] if no new scope hints found.'
)

DEPTH3_SYSTEM_PROMPT = (
    _DIALECT_RING
    + "You are the vulnerability enumeration module of Reconesis. "
    "You have deep service fingerprints for each host. "
    "Now find specific weaknesses — anonymous access, default configurations, "
    "exposed management consoles, known service vulnerabilities. "
    "Use targeted passive NSE scripts appropriate to each service type. "
    "Do NOT use brute-force scripts. "
    "Do NOT re-scan ports or services already enumerated in previous iterations.\n\n"
    "Reply ONLY with valid JSON — no prose, no code fences:\n"
    '{\n  "command": "<nmap string>",\n'
    '  "rationale": "<one sentence>",\n'
    '  "continue": <true|false>,\n'
    '  "new_targets": ["<ip or cidr>", ...]\n}\n\n'
    '"continue": false when no further vulnerability enumeration is possible.\n'
    '"new_targets": [] if no new scope hints found.'
)

_DEPTH_PROMPTS = {
    1: DEPTH1_SYSTEM_PROMPT,
    2: DEPTH2_SYSTEM_PROMPT,
    3: DEPTH3_SYSTEM_PROMPT,
}


class GroqAgent:
    _SYSTEM_PROMPTS = {
        "scout": (
            "You are the 'Scout' module of Reconesis, an automated network reconnaissance engine. "
            "Your objective is broad network mapping and asset discovery. "
            "You must balance speed, stealth, and coverage. Prefer techniques that minimize "
            "network noise (e.g., SYN stealth scans, ping sweeps, ARP discovery) while maximizing "
            "host and service detection. Adapt your approach based on the target scope and context provided."
            + _OUTPUT_RULE
        ),
        "hunter_database": _build_hunter_prompt(
            "Database Server",
            "deeply investigate: identify the exact database engine and version, "
            "check for authentication weaknesses, and enumerate database-specific vulnerabilities. "
            "Select scripts appropriate for the specific database type detected",
            "mysql-info, mysql-empty-password, ms-sql-info, pgsql-brute, mongodb-info, redis-info",
        ),
        "hunter_mail": _build_hunter_prompt(
            "Mail Server",
            "verify mail services and check for critical misconfigurations: "
            "open relays, SMTP user enumeration, and STARTTLS support. "
            "Scan all standard mail ports: 25, 110, 143, 465, 587, 993, 995",
            "smtp-open-relay, smtp-enum-users, smtp-commands, smtp-vuln-cve2010-4344, "
            "imap-capabilities, pop3-capabilities",
        ),
        "hunter_infra": _build_hunter_prompt(
            "Network Infrastructure (Router/Firewall)",
            "fingerprint the device, identify the firmware version, and check for "
            "exposed management interfaces, default credentials, and SNMP community strings",
            "banner, ssh-auth-methods, http-title, snmp-brute, snmp-info, telnet-brute",
        ),
        "hunter_ldap": _build_hunter_prompt(
            "Active Directory / LDAP Server",
            "enumerate directory services, identify exposed accounts, check for "
            "anonymous bind vulnerabilities, and identify privilege escalation vectors. "
            "Scan all standard LDAP ports: 389, 636, 3268, 3269, 88",
            "ldap-search, ldap-brute, ldap-rootdse, msrpc-enum, smb-security-mode, "
            "krb5-enum-users, dns-srv-enum",
        ),
        "hunter_jump": _build_hunter_prompt(
            "Jump Host / Bastion Server",
            "identify SSH hardening posture, check for weak authentication, "
            "enumerate supported key exchange and cipher algorithms, and identify whether "
            "multi-factor authentication is enforced. "
            "Scan both standard SSH (22) and non-standard bastion ports (2222, 22222)",
            "ssh-auth-methods, ssh-hostkey, ssh2-enum-algos, banner",
        ),
        "hunter_app": _build_hunter_prompt(
            "Application Server",
            "identify the middleware platform, find exposed management "
            "consoles, check for Java deserialization vulnerabilities, and enumerate "
            "deployed applications. "
            "Scan app server ports: 8080, 8443, 4848, 9990, 7001, 7002",
            "http-title, http-enum, http-auth-finder, http-default-accounts, "
            "http-vuln-cve2010-0738, ajp-headers, ajp-request",
        ),
        "hunter_web": _build_hunter_prompt(
            "Web Server",
            "identify the web technology stack, enumerate directories "
            "and virtual hosts, check for common web vulnerabilities, and find exposed "
            "admin interfaces. "
            "Scan all common web ports: 80, 443, 8080, 8443, 8000, 8888",
            "http-title, http-headers, http-enum, http-methods, http-server-header, "
            "http-vuln-cve2017-5638, http-shellshock, http-robots.txt, http-git",
        ),
        "hunter_iot": _build_hunter_prompt(
            "IoT IP Camera",
            "enumerate RTSP stream URLs, identify the camera make/model, "
            "check for default credentials on the web management interface, and detect "
            "known firmware vulnerabilities. "
            "Scan all standard camera ports: 554 (RTSP), 1935 (RTMP), 8000, 8080, 8888 "
            "(management), 8899 (ONVIF), 37777 (Dahua)",
            "rtsp-url-brute, rtsp-methods, http-default-accounts, http-auth-finder, "
            "http-title, http-methods",
        ),
        "hunter_nas": _build_hunter_prompt(
            "NAS Appliance",
            "enumerate file shares, check for default credentials on the web "
            "management interface, test for anonymous NFS and SMB access, and detect known "
            "firmware vulnerabilities (including QNAP QLocker/DeadBolt and Synology CVEs). "
            "SMB enumeration is included because NAS devices universally offer SMB shares "
            "alongside NFS and AFP. "
            "Scan all standard NAS ports: 21 (FTP), 22 (SSH), 80, 139, 443, 445 (SMB), "
            "548 (AFP), 873 (rsync), 2049 (NFS), 3260 (iSCSI), 5000, 5001 (Synology DSM), "
            "8080 (QNAP)",
            "smb-enum-shares, smb-security-mode, nfs-ls, nfs-showmount, ftp-anon, "
            "http-default-accounts, http-auth-finder, http-title",
        ),
        "hunter_winfs": _build_hunter_prompt(
            "Windows File Server",
            "enumerate SMB shares and their permissions, verify SMB signing "
            "enforcement, check for null session access, test for EternalBlue (MS17-010) and "
            "other critical SMB vulnerabilities, and enumerate RPC endpoints. "
            "Scan all standard Windows file sharing ports: 135 (MSRPC), 139 (NetBIOS), "
            "445 (SMB), 3389 (RDP)",
            "smb-enum-shares, smb-vuln-ms17-010, smb-security-mode, smb-os-discovery, "
            "msrpc-enum, smb-vuln-ms10-054",
        ),
        "hunter_dns": _build_hunter_prompt(
            "DNS Server",
            "test for zone transfer (AXFR) misconfiguration, verify whether "
            "open recursion is enabled, fingerprint the resolver version via NSID, and detect "
            "DNS cache snooping vulnerabilities. "
            "Scan all standard DNS server ports: 53 (DNS), 953 (BIND RNDC)",
            "dns-zone-transfer, dns-nsid, dns-cache-snoop, dns-recursion, dns-service-discovery",
        ),
        "hunter_generic": _build_hunter_prompt(
            "Web Server or general host",
            "identify the web technology stack, check for common web vulnerabilities, "
            "and enumerate exposed endpoints",
            "http-title, http-headers, http-enum, http-methods, http-vuln-cve2017-5638, vuln",
        ),
    }

    _CLASSIFY_SYSTEM_PROMPT = (
        _DIALECT_RING + "You are a network asset classifier for a penetration testing tool.\n"
        "You will receive a list of hosts in compressed dialect format. Each host\n"
        "includes port data, OS fingerprint, and static scoring signals on the M: line.\n\n"
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
        "- Return ONLY a valid JSON array. No prose, no markdown, no code fences.\n"
        "T and C shown are static scorer guesses — verify against M: signals and port data, correct if wrong."
    )

    _REPORT_SECTION1_SYSTEM = (
        _DIALECT_RING + "You are a Senior Cybersecurity Analyst reviewing automated network reconnaissance results.\n"
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
        _DIALECT_RING + "You are a Senior Cybersecurity Analyst reviewing automated network reconnaissance results.\n"
        "Write the SECOND HALF of a professional report in Markdown. Use formal technical English. No emoji.\n\n"
        "Write ONLY these two sections — nothing else:\n\n"
        "# Risk Assessment\n"
        "Per-asset risk analysis for each CRITICAL and HIGH host. "
        "If exploit data is present for any port (shown as [yr-id:cvss:src] entries after the port line), include a CVE table with columns: "
        "CVE ID | CVSS Score | Affected Service | Source. "
        "Highlight CVEs with CVSS >= 7.0 as HIGH or CRITICAL severity.\n\n"
        "# Recommended Remediation Actions\n"
        "Prioritized, actionable steps to mitigate identified risks. Reference specific CVE IDs where applicable.\n\n"
        "Do NOT repeat the executive summary or asset inventory table."
    )

    def __init__(self, event_callback=None):
        self.logger = logging.getLogger("GroqAgent")
        self.api_url = Config.GROQ_API_URL
        self.api_key = Config.GROQ_API_KEY
        self.model = Config.GROQ_MODEL
        self._emit = event_callback or (lambda t, d: None)
        self._call_id = 1
        # PERF: connection reuse — eliminates per-call TCP+TLS handshake (M-5)
        self._session = requests.Session()

    def _build_history_context(self, previous_findings: list) -> str:
        """Build the compressed history context block appended to LLM user prompts.

        Delegates to ToonDialect.compress_history() which caps output to the last two
        scan depths. Returns an empty string when there are no prior findings so callers
        can unconditionally concatenate the result.

        Args:
            previous_findings: List of scan-history entry dicts as stored in
                               ReconesisEngine.scan_history.

        Returns:
            A newline-prefixed summary string, or empty string if previous_findings is empty.
        """
        if not previous_findings:
            return ""
        summary = ToonDialect.compress_history(previous_findings)
        return f"\n\nPrevious scan findings (showing last 2 depths):\n{summary}\n"

    def _select_system_prompt(self, phase: str, types_present: set) -> str:
        """Select the correct system prompt for the given scan phase and target asset types.

        For discovery and port_scan phases always returns the Scout prompt. For the hunter
        phase, iterates _TYPE_PROMPT_MAP in insertion order (database > mail > infra ...)
        so the highest-priority asset type wins when multiple types are present. Falls back
        to hunter_generic when no type substring matches.

        Args:
            phase: Scan phase string — one of "discovery", "port_scan", or "hunter".
            types_present: Set of asset type strings (lowercased) from critical_targets.

        Returns:
            The selected system prompt string from _SYSTEM_PROMPTS.
        """
        if phase in ("discovery", "port_scan"):
            return self._SYSTEM_PROMPTS["scout"]

        types_lower = {t.lower() for t in types_present}
        for map_key, prompt_key in _TYPE_PROMPT_MAP.items():
            if any(map_key in t for t in types_lower):
                return self._SYSTEM_PROMPTS[prompt_key]
        return self._SYSTEM_PROMPTS["hunter_generic"]

    def _build_user_prompt(self, phase: str, context_data: dict, history_context: str) -> str:
        """Build the user-facing prompt body for the given scan phase.

        Generates a phase-specific instruction block that tells the LLM what targets to
        scan and what objective to pursue. The history_context string (from
        _build_history_context) is appended verbatim so the LLM can avoid re-scanning
        already-explored hosts.

        Args:
            phase: Scan phase — "discovery", "port_scan", or "hunter".
            context_data: Dict of phase-specific keys; "target_scope" for discovery,
                          "live_hosts" for port_scan, "critical_targets" for hunter.
            history_context: Pre-formatted history block to append (may be empty string).

        Returns:
            The complete user prompt string to pass to _query_groq().
        """
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

        user_prompt = ToonDialect.serialize_classify(evidence_bundles)
        try:
            result, finish_reason = self._query_groq(
                self._CLASSIFY_SYSTEM_PROMPT,
                user_prompt,
                timeout=120,
                max_tokens=4096,
                temperature=0,
            )
            if not result:
                self.logger.warning("classify_hosts: empty or error response from Groq")
                return []
            return json.loads(result)
        except ReconesisAPIError as e:
            self.logger.warning(f"classify_hosts API error (reason=api_error): {e}")
            return []
        except (ReconesisParseError, json.JSONDecodeError) as e:
            self.logger.warning(f"classify_hosts parse error (reason=parse_error): {e}")
            return []
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
        dialect_str = ToonDialect.serialize_report(toon_data)
        user_prompt = (
            "Below is the complete scan data. "
            "Analyze every host, paying special attention to assets classified as Critical or High.\n\n"
            f"SCAN DATA:\n{dialect_str}"
        )

        try:
            section1, reason1 = self._query_groq(
                self._REPORT_SECTION1_SYSTEM, user_prompt, timeout=120, max_tokens=4096,
                strip_backticks=False
            )
            if not section1:
                raise ValueError("Section 1 call failed")

            section2, reason2 = self._query_groq(
                self._REPORT_SECTION2_SYSTEM, user_prompt, timeout=120, max_tokens=4096,
                strip_backticks=False
            )
            if not section2:
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
            response = self._session.post(self.api_url, headers=headers, json=payload, timeout=timeout)
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
                    # Retry up to 3 times, each time waiting the server-suggested delay.
                    last_exc = e
                    for attempt in range(1, 4):
                        match = re.search(r"try again in (\d+\.?\d*)s",
                                          last_exc.response.text if last_exc.response else "")
                        wait = float(match.group(1)) + 1 if match else min(30, 5 * attempt)
                        self.logger.warning(
                            f"Rate limited — waiting {wait:.1f}s (attempt {attempt}/3)"
                        )
                        time.sleep(wait)
                        try:
                            response = self._session.post(
                                self.api_url, headers=headers, json=payload, timeout=timeout
                            )
                            response.raise_for_status()
                            data = response.json()
                            choice = data["choices"][0]
                            result = choice["message"]["content"].strip()
                            if strip_backticks:
                                result = result.replace("```", "").replace("`", "").strip()
                            return result, choice.get("finish_reason", "stop")
                        except requests.exceptions.HTTPError as retry_e:
                            if retry_e.response is not None and retry_e.response.status_code == 429:
                                last_exc = retry_e
                                continue
                            raise ReconesisAPIError(
                                f"API error after rate-limit retry: {retry_e}"
                            ) from retry_e
                    raise ReconesisAPIError(
                        f"Rate limit persisted after 3 retries"
                    ) from last_exc
                if status_code == 401:
                    self.logger.error("API authentication failed — check your GROQ_API_KEY")
            raise ReconesisAPIError(f"Groq API HTTP error ({status_code}): {e}") from e
        except requests.exceptions.Timeout:
            self.logger.error(f"Groq API request timed out after {timeout} seconds")
            raise ReconesisAPIError("Groq API request timed out")
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Groq API connection error: {e}")
            raise ReconesisAPIError(f"Groq API connection error: {e}") from e
        except (KeyError, ValueError) as e:
            self.logger.error(f"Failed to parse Groq API response: {e}")
            raise ReconesisParseError(f"Failed to parse Groq API response: {e}") from e

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
            "For each asset, if exploit data is present for any port "
            "(shown as [yr-id:cvss:src] entries after the port line), include a CVE table with "
            "columns: CVE ID | CVSS Score | Affected Service | Source. "
            "Highlight any CVE with CVSS >= 7.0 as HIGH or CRITICAL severity.\n\n"
            "# Recommended Remediation Actions\n"
            "Prioritized, actionable steps to mitigate the identified risks. "
            "Reference specific CVE IDs where applicable.\n\n"
            "# Conclusion\n"
            "Final summary and overall risk posture assessment."
        )

        system_prompt = _DIALECT_RING + system_prompt

        dialect_str = ToonDialect.serialize_report(toon_data)
        user_prompt = (
            "Below is the complete scan data. "
            "Analyze every host, paying special attention to assets classified as Critical or High. "
            "Identify patterns, exposed services, and potential attack vectors.\n\n"
            f"SCAN DATA:\n{dialect_str}"
        )

        return system_prompt, user_prompt

    def decide_for_depth(self, context: dict) -> dict:
        """Select a scan command for the given depth context.

        Builds a user prompt from the scoped target hosts (via ToonDialect.render_with_gaps),
        depth purpose string, and cross-depth scan history. Raises ReconesisAPIError on API
        failure and ReconesisParseError on unparseable response.

        Args:
            context: dict with keys depth (int), depth_purpose (str), target_hosts (list[dict]),
                     hosts (list[dict]), scan_history (list), gap_map (dict, pre-computed by
                     _mini_loop on the engine side).

        Returns:
            Parsed decision dict with keys: command, rationale, continue, new_targets.
        """
        depth = context["depth"]
        system_prompt = _DEPTH_PROMPTS.get(depth, DEPTH1_SYSTEM_PROMPT)

        target_hosts = context.get("target_hosts", [])
        gap_map = context.get("gap_map", {})
        toon_block = ToonDialect.render_with_gaps(target_hosts, gap_map)

        purpose = context.get("depth_purpose", "")
        history_block = self._build_history_context(context.get("scan_history", []))
        user_content = f"{purpose}\n\n{toon_block}{history_block}"

        try:
            result, _ = self._query_groq(
                system_prompt=system_prompt,
                user_prompt=user_content,
                strip_backticks=False,
            )
        except (ReconesisAPIError, ReconesisParseError):
            raise
        except Exception as e:
            raise ReconesisAPIError(f"decide_for_depth: unexpected API error: {e}") from e
        if not result:
            raise ReconesisParseError("decide_for_depth: empty response from Groq")
        raw = result.strip()
        if raw.startswith("```"):
            raw = re.sub(r"^```[a-z]*\n?", "", raw)
            raw = re.sub(r"\n?```$", "", raw)
        try:
            decision = json.loads(raw)
            if "command" not in decision:
                raise ValueError("Missing 'command' key")
            decision.setdefault("new_targets", [])
            decision.setdefault("continue", True)
            return decision
        except (json.JSONDecodeError, ValueError) as e:
            raise ReconesisParseError(f"decide_for_depth: failed to parse JSON: {e}") from e
