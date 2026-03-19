
import logging
import json
import time
from src.core.toon import TOONParser
from src.core.executor import NmapExecutor
from src.core.agent import GroqAgent
from src.utils.criticality import CriticalityAssessor
from src.utils.exploit_lookup import ExploitLookup
from src.utils.config import Config


class ReconesisEngine:
    def __init__(self, event_callback=None):
        """
        Args:
            event_callback: optional callable(event_type, data) for streaming
                            progress to the dashboard (SSE events).
        """
        self.logger = logging.getLogger("ReconesisEngine")
        self.parser = TOONParser()
        self.agent = GroqAgent()
        self.assessor = CriticalityAssessor()
        self.exploit_lookup = ExploitLookup()
        self.scan_history = []

        # Dashboard event stream hook
        self._emit = event_callback if event_callback else lambda t, d: None

        # Executor constructed AFTER self._emit so it can receive the callback
        self.executor = NmapExecutor(event_callback=self._emit)

        # Evaluation metrics (proposal §5)
        self.metrics = {
            "start_time": None,
            "end_time": None,
            "depth": 0,
            "total_hosts": 0,
            "critical_hosts": 0,
            "total_packets": 0,
            "time_per_host": 0.0,
            "critical_ratio": 0.0
        }

    @staticmethod
    def _get_own_ips() -> set:
        """Returns all local IP addresses so they can be excluded from scan targets."""
        import socket
        own_ips = {'127.0.0.1', '::1'}

        # Method 1: hostname resolution (catches primary interface)
        try:
            hostname = socket.gethostname()
            for info in socket.getaddrinfo(hostname, None):
                own_ips.add(info[4][0])
        except Exception:
            pass

        # Method 2: UDP connect trick — finds the IP used to reach the outside world
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(('8.8.8.8', 80))
                own_ips.add(s.getsockname()[0])
        except Exception:
            pass

        return own_ips

    def _log(self, msg: str, level: str = "info"):
        """Log and emit to dashboard simultaneously."""
        getattr(self.logger, level)(msg)
        self._emit("log", {"level": level, "message": msg})

    def start_scan(self, target: str):
        self.metrics["start_time"] = time.time()
        self._log(f"🚀 Starting Reconesis on target: {target}")
        self._emit("status", {"phase": "discovery", "target": target})

        seen_hashes = set()          # Hash-saturation termination (proposal §4.3.4)
        depth = 0
        all_detailed_hosts = []

        # ---------------------------------------------------------------
        # STATE MACHINE LOOP — max depth = Config.MAX_DEPTH (default: 3)
        # ---------------------------------------------------------------
        while depth < Config.MAX_DEPTH:
            depth += 1
            self.metrics["depth"] = depth
            self._log(f"--- Depth Level {depth}/{Config.MAX_DEPTH} ---")

            # -----------------------------------------------------------
            # PHASE 1: DISCOVERY (Scout Mode)
            # -----------------------------------------------------------
            if depth == 1:
                self._log("PHASE 1: SCOUT MODE — Initial Host Discovery")
                self._emit("status", {"phase": "discovery"})

                discovery_cmd = self.agent.generate_strategy({
                    "phase": "discovery",
                    "target_scope": target,
                    "previous_findings": self.scan_history
                })
                self._log(f"Agent command: {discovery_cmd}")

                if not discovery_cmd:
                    self._log("Agent returned no command. Aborting.", "error")
                    return

                raw_xml, pkts = self.executor.execute(discovery_cmd)
                self.metrics["total_packets"] += pkts
                if not raw_xml:
                    self._log("Discovery scan produced no output.", "error")
                    return

                toon_hosts = self.parser.parse(raw_xml)
                if not toon_hosts:
                    self._log("No live hosts found. Scan complete.")
                    return

                live_ips = [h['target'] for h in toon_hosts]

                # Exclude own IPs — don't scan the machine running Reconesis
                own_ips = self._get_own_ips()
                excluded = [ip for ip in live_ips if ip in own_ips]
                if excluded:
                    self._log(f"Excluding own IP(s) from scan: {excluded}")
                    live_ips = [ip for ip in live_ips if ip not in own_ips]

                self._log(f"Discovered {len(live_ips)} live hosts: {live_ips}")
                self._emit("hosts_found", {"hosts": live_ips})

            # -----------------------------------------------------------
            # PHASE 2: PORT SCAN & ASSET CLASSIFICATION (with retry logic)
            # -----------------------------------------------------------
            self._log("PHASE 2: SCOUT MODE — Port Scan & Asset Classification")
            self._emit("status", {"phase": "assessment"})

            max_retries = 2
            phase2_success = False
            detailed_hosts = []

            for attempt in range(1, max_retries + 1):
                port_scan_cmd = self.agent.generate_strategy({
                    "phase": "port_scan",
                    "live_hosts": live_ips,
                    "previous_findings": self.scan_history
                })
                self._log(f"Agent command (attempt {attempt}/{max_retries}): {port_scan_cmd}")

                if not port_scan_cmd:
                    self._log(f"Agent returned no port scan command (attempt {attempt}/{max_retries}).", "warning")
                    if attempt < max_retries:
                        # Exponential backoff: 1s, 2s
                        backoff = 2 ** (attempt - 1)
                        self._log(f"Retrying in {backoff} seconds...")
                        time.sleep(backoff)
                    continue

                raw_xml_detailed, pkts = self.executor.execute(port_scan_cmd)
                self.metrics["total_packets"] += pkts

                if not raw_xml_detailed:
                    self._log(f"Port scan produced no output (attempt {attempt}/{max_retries}).", "warning")
                    if attempt < max_retries:
                        backoff = 2 ** (attempt - 1)
                        self._log(f"Retrying in {backoff} seconds...")
                        time.sleep(backoff)
                    continue

                # Success! Parse and proceed
                detailed_hosts = self.parser.parse(raw_xml_detailed)
                phase2_success = True
                self._log(f"Phase 2 succeeded on attempt {attempt}")
                break

            # If Phase 2 failed after all retries, skip to Phase 4 with graceful degradation
            if not phase2_success:
                self._log("Phase 2 port scan FAILED after all retries. Skipping to Phase 4 with partial data.", "warning")
                self._log("⚠️ Results are INCOMPLETE — Phase 2 and Phase 3 were skipped due to port scan failure.")
                self._emit("status", {"phase": "reporting"})

                # Phase 4 with partial/no data
                self._log("PHASE 4: Final AI Analysis & Report Generation (with partial data)")
                if all_detailed_hosts:
                    report = self.agent.analyze_results(all_detailed_hosts)
                else:
                    report = "# Reconesis Scan Report\n\n**No reconnaissance data available** — Port scan phase failed and could not be recovered. Please check your Groq API key and network connectivity."

                self._emit("report", {"content": report})
                with open("scan_report.md", "w") as f:
                    f.write(report)

                self.metrics["end_time"] = time.time()
                self._emit("done", {"message": "Reconesis scan completed with errors (see report)."})
                self._log("❌ Reconesis failed to complete full reconnaissance due to Phase 2 failure.")
                print("\n=== SCAN REPORT (INCOMPLETE) ===\n")
                print(report)
                return

            # --- Hash Saturation Check (proposal §4.3.4) ---
            current_hash = self.parser.compute_hash(detailed_hosts)
            if current_hash in seen_hashes:
                self._log("Hash saturation detected — no new information. Stopping loop.")
                break
            seen_hashes.add(current_hash)
            all_detailed_hosts = detailed_hosts

            # Apply criticality classification
            critical_targets = []
            classified = []
            for host in detailed_hosts:
                assessment = self.assessor.assess(host)
                host['criticality'] = assessment['level']
                host['type'] = assessment['type']
                host['metrics'] = assessment['reasons']
                classified.append(host)

                self._log(
                    f"Host {host['target']} → [{assessment['type']}] ({assessment['level']})"
                )
                self._emit("host_assessed", {
                    "ip": host['target'],
                    "type": assessment['type'],
                    "criticality": assessment['level'],
                    "ports": host['ports'],
                    "reasons": assessment['reasons']
                })

                if assessment['level'] in ["CRITICAL", "HIGH"]:
                    critical_targets.append({"ip": host['target'], "type": assessment['type']})

            self.metrics["total_hosts"] = len(detailed_hosts)
            self.metrics["critical_hosts"] = len(critical_targets)

            # --- Populate scan_history so subsequent LLM calls get real context ---
            self.scan_history.append({
                "depth": depth,
                "hosts": [
                    {
                        "ip": h["target"],
                        "type": h.get("type", "Unknown"),
                        "criticality": h.get("criticality", "UNKNOWN"),
                        "ports": [p["port"] for p in h.get("ports", [])]
                    }
                    for h in classified
                ]
            })

            # --- Criticality Fulfilment Check (proposal §4.3.4) ---
            if not critical_targets:
                self._log("No critical targets found — termination criteria met.")
                break

            # -----------------------------------------------------------
            # PHASE 3: HUNTER MODE (Deep Scan on Critical Assets)
            # -----------------------------------------------------------
            self._log(f"PHASE 3: HUNTER MODE — Deep scan on {len(critical_targets)} critical assets")
            self._emit("status", {"phase": "hunter", "targets": critical_targets})

            hunter_cmd = self.agent.generate_strategy({
                "phase": "hunter",
                "critical_targets": critical_targets,
                "previous_findings": self.scan_history
            })
            self._log(f"Agent command: {hunter_cmd}")

            if not hunter_cmd:
                self._log("Agent returned no hunter command — stopping loop.", "warning")
                break

            hunter_xml, pkts = self.executor.execute(hunter_cmd, inject_vulners=True)
            self.metrics["total_packets"] += pkts
            if hunter_xml:
                hunter_hosts = self.parser.parse(hunter_xml)
                # Merge hunter findings into our host records
                hunter_map = {h['target']: h for h in hunter_hosts}
                for host in all_detailed_hosts:
                    if host['target'] in hunter_map:
                        # Merge hunter port data: replace existing ports with richer
                        # hunter versions (which carry NSE script output), add new ones.
                        new_ports = hunter_map[host['target']].get('ports', [])
                        existing_port_idx = {p['port']: i for i, p in enumerate(host.get('ports', []))}
                        for p in new_ports:
                            if p['port'] in existing_port_idx:
                                host['ports'][existing_port_idx[p['port']]] = p
                            else:
                                host['ports'].append(p)
                        self._emit("host_enriched", {
                            "ip": host['target'],
                            "ports": host['ports']
                        })
            else:
                self._log("Hunter scan produced no output.", "warning")

            # Update live_ips from current results so the next depth iteration
            # scans the same (now fully enriched) host set — BUG-03 fix.
            live_ips = [h['target'] for h in all_detailed_hosts]
            self._log(f"Depth {depth} complete. Continuing OODA loop...")

        # ---------------------------------------------------------------
        # CVE ENRICHMENT — runs after all scans, before report generation
        # ---------------------------------------------------------------
        self._log("CVE Enrichment: correlating NSE script output and CPE lookups...")
        self._emit("status", {"phase": "cve_enrichment"})

        all_detailed_hosts = self.exploit_lookup.enrich_from_nse(all_detailed_hosts)
        all_detailed_hosts = self.exploit_lookup.enrich_from_cpe(all_detailed_hosts)

        # Emit per-host CVE data to the dashboard
        for host in all_detailed_hosts:
            cves = []
            for port in host.get("ports", []):
                for exploit in port.get("exploits", []):
                    cves.append({
                        "port": port["port"],
                        "service": port["service"],
                        "cve": exploit.get("cve", ""),
                        "cvss": exploit.get("cvss", 0),
                        "source": exploit.get("source", "")
                    })
            if cves:
                self._emit("cves_found", {"ip": host["target"], "cves": cves})
                self._log(f"  {host['target']}: {len(cves)} CVE(s) found")

        # ---------------------------------------------------------------
        # PHASE 4: FINAL REPORT
        # ---------------------------------------------------------------
        self._log("PHASE 4: Final AI Analysis & Report Generation")
        self._emit("status", {"phase": "reporting"})

        if not all_detailed_hosts:
            self._log("No host data to report.", "warning")
            return

        report = self.agent.analyze_results(all_detailed_hosts)
        self._emit("report", {"content": report})

        # Save outputs
        with open("scan_results.json", "w") as f:
            json.dump(all_detailed_hosts, f, indent=2)

        with open("scan_report.md", "w") as f:
            f.write(report)

        # --- Finalize Metrics ---
        self.metrics["end_time"] = time.time()
        elapsed = self.metrics["end_time"] - self.metrics["start_time"]
        total_hosts = self.metrics["total_hosts"]
        critical = self.metrics["critical_hosts"]

        if total_hosts > 0:
            self.metrics["time_per_host"] = round(elapsed / total_hosts, 2)
            self.metrics["critical_ratio"] = round((critical / total_hosts) * 100, 1)

        self._emit("metrics", self.metrics)
        self._emit("done", {"message": "Reconesis scan complete."})
        self._log(f"✅ Reconesis complete. {total_hosts} hosts scanned, {critical} critical found.")
        self._log(f"   Time/host: {self.metrics['time_per_host']}s | Depth: {depth}")

        print("\n=== FINAL REPORT ===\n")
        print(report)
        self.logger.info("Reconesis Task Completed.")
