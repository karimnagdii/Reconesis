
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
                "Objective: Identify open ports and running services on these hosts to classify them.\n"
                "Requirements:\n"
                "- Use SYN stealth scan (-sS) with version detection (-sV)\n"
                "- Scan the top 1000 ports (--top-ports 1000)\n"
                "- List all target IPs space-separated at the END of the command\n"
                f"- Correct syntax example: nmap -sS -sV --top-ports 1000 {targets_str}"
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

        return self._query_groq(system_prompt, user_prompt)

    def analyze_results(self, toon_data: list) -> str:
        """
        Analyzes the final TOON data to produce a summary report.
        """
        system_prompt, user_prompt = self._build_analysis_prompt(toon_data)
        return self._query_groq(system_prompt, user_prompt)

    def _query_groq(self, system_prompt: str, user_prompt: str) -> str:
        """
        Sends a request to the Groq API using proper system/user message roles
        for stronger instruction-following.
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
        try:
            response = requests.post(self.api_url, headers=headers, json=payload, timeout=30)
            response.raise_for_status()
            data = response.json()
            # Strip markdown code fences if the LLM wraps output
            result = data["choices"][0]["message"]["content"].strip()
            result = result.replace("```", "").replace("`", "").strip()
            return result
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Groq API error: {e}")
            if hasattr(e, 'response') and e.response is not None:
                self.logger.error(f"Response body: {e.response.text}")
            return ""

    def _build_analysis_prompt(self, toon_data: list) -> tuple:
        """
        Builds a structured analysis prompt with enforced report sections.
        Returns (system_prompt, user_prompt) tuple.
        """
        system_prompt = (
            "You are a Senior Cybersecurity Analyst reviewing the results of an automated "
            "network reconnaissance scan performed by the Reconesis engine. "
            "Write a professional Final Report in Markdown format. "
            "You MUST structure the report with these exact sections:\n\n"
            "# Executive Summary\n"
            "A brief overview of the scan scope, methodology, and key findings.\n\n"
            "# Network Topology Overview\n"
            "A summary of discovered hosts and their roles on the network.\n\n"
            "# Critical Assets Identified\n"
            "A table of critical infrastructure found (Routers, Firewalls, Mail Servers, Databases) "
            "with their IP, type, open ports, and risk level.\n\n"
            "# Risk Assessment\n"
            "Per-asset risk analysis with specific vulnerability details and potential impact.\n\n"
            "# Recommended Remediation Actions\n"
            "Prioritized, actionable steps to mitigate the identified risks.\n\n"
            "# Conclusion\n"
            "Final summary and overall risk posture assessment."
        )

        user_prompt = (
            "Below is the complete scan data in TOON (Target-Oriented Object Notation) format. "
            "Analyze every host, paying special attention to assets classified as Critical or High. "
            "Identify patterns, exposed services, and potential attack vectors.\n\n"
            f"SCAN DATA:\n{json.dumps(toon_data, indent=2)}"
        )

        return system_prompt, user_prompt
