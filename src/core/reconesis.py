
import re
import logging
import json
import time
from src.core.toon import TOONParser
from src.core.executor import NmapExecutor
from src.core.agent import GroqAgent
from src.utils.criticality import CriticalityAssessor
from src.utils.exploit_lookup import ExploitLookup
from src.utils.config import Config
from src.utils.exceptions import ReconesisAPIError, ReconesisParseError


INTERESTING_PORTS = {21, 22, 23, 25, 80, 443, 445, 1433, 3306, 3389, 5432, 6379}

_DEPTH1_PURPOSE = (
    "Build a complete picture of the network. Discover all device roles, identify "
    "additional subnets, detect firewall presence, and map the full attack surface. "
    "Vary port sets and scan techniques across sub-iterations to reveal hosts that "
    "earlier scans missed. Choose ports that would expose: Routers, Firewalls, "
    "IoT Cameras, Active Directory/LDAP, Database Servers, Mail Servers, DNS Servers, "
    "NAS Appliances, Windows File Servers, Jump Hosts, Web Servers, Application Servers. "
    "Do not use -p- or --top-ports."
)

_DEPTH2_PURPOSE = (
    "You have a classified network map. These are confirmed CRITICAL or HIGH assets. "
    "Go deeper — enumerate exact service versions, identify exposed management interfaces, "
    "check for service-specific misconfigurations. Choose ports meaningful to each host's "
    "classified type. Use passive NSE scripts only. No brute-force scripts."
)

_DEPTH3_PURPOSE = (
    "You have deep service fingerprints on these high-value targets. Now find specific "
    "weaknesses — anonymous access, default configurations, exposed management consoles, "
    "known service vulnerabilities. Use targeted passive NSE scripts. No brute-force. "
    "Do not re-cover ground already explored in depth 2."
)

_VALID_TYPES = {
    "Database Server", "Mail Server", "Firewall", "Router",
    "Active Directory / LDAP", "Jump Host", "Web Server", "Application Server",
    "IoT Camera", "NAS Appliance", "Windows File Server", "DNS Server", "Generic Host",
}
_VALID_CRITICALITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}


class ReconesisEngine:
    def __init__(self, event_callback=None):
        """
        Args:
            event_callback: optional callable(event_type, data) for streaming
                            progress to the dashboard (SSE events).
        """
        self.logger = logging.getLogger("ReconesisEngine")
        self.parser = TOONParser()
        self.assessor = CriticalityAssessor()
        self.exploit_lookup = ExploitLookup()
        self.scan_history = []
        self._host_map = {}       # Accumulates host data across all phases and depths

        # Dashboard event stream hook
        self._emit = event_callback if event_callback else lambda t, d: None

        # Agent and Executor constructed AFTER self._emit so they can receive the callback
        self.agent = GroqAgent(event_callback=self._emit)
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

    @staticmethod
    def _extract_port_set(command: str) -> set:
        """Extract all port numbers from the -p argument of an nmap command."""
        m = re.search(r'-p\s+(\S+)', command)
        if not m:
            return set()
        ports = set()
        for part in m.group(1).split(','):
            part = re.sub(r'^[TUtu]:', '', part.strip())
            if '-' in part:
                try:
                    lo, hi = part.split('-', 1)
                    ports.update(range(int(lo), min(int(hi) + 1, 65536)))
                except ValueError:
                    pass
            else:
                try:
                    ports.add(int(part))
                except ValueError:
                    pass
        return ports

    @staticmethod
    def _is_richer(new_port: dict, existing_port: dict) -> bool:
        """Returns True if new_port adds version, product, script, or exploit data that existing lacks."""
        if new_port.get("version") and not existing_port.get("version"):
            return True
        if new_port.get("product") and not existing_port.get("product"):
            return True
        if new_port.get("scripts") and not existing_port.get("scripts"):
            return True
        if new_port.get("exploits") and not existing_port.get("exploits"):
            return True
        return False

    @property
    def _all_hosts(self) -> list:
        return list(self._host_map.values())

    @_all_hosts.setter
    def _all_hosts(self, hosts: list):
        filtered = [h for h in hosts if "target" in h]
        if len(filtered) < len(hosts):
            self.logger.warning(
                f"_all_hosts setter: dropped {len(hosts) - len(filtered)} host(s) missing 'target' key"
            )
        self._host_map = {h["target"]: h for h in filtered}

    def _merge_host(self, new_host: dict) -> bool:
        """Merge new_host into self._host_map. Returns True if anything changed."""
        ip = new_host["target"]
        if ip not in self._host_map:
            self._host_map[ip] = new_host
            return True
        existing = self._host_map[ip]
        changed = False
        port_map = {p["port"]: p for p in existing.get("ports", [])}
        for p in new_host.get("ports", []):
            if p["port"] not in port_map or ReconesisEngine._is_richer(p, port_map[p["port"]]):
                port_map[p["port"]] = p
                changed = True
        existing["ports"] = list(port_map.values())
        new_os = new_host.get("os", {})
        existing_os = existing.get("os", {})
        if new_os.get("accuracy", 0) > existing_os.get("accuracy", 0):
            existing["os"] = new_os
            changed = True
        return changed

    def _compute_gaps(self) -> list:
        """Returns a list of gap dicts — one per host that has unknowns.
        Empty list means nothing left to learn; the loop should terminate."""
        gaps = []
        for host in self._host_map.values():
            host_gaps = []
            if host.get("os", {}).get("accuracy", 0) < 80:
                host_gaps.append("os_unknown")
            for p in host.get("ports", []):
                if not p.get("version"):
                    host_gaps.append(f"no_version:{p['port']}/{p['service']}")
                if not p.get("scripts") and p["port"] in INTERESTING_PORTS:
                    host_gaps.append(f"no_scripts:{p['port']}/{p['service']}")
            if host_gaps:
                gaps.append({
                    "ip": host["target"],
                    "type": host.get("type", "Unknown"),
                    "criticality": host.get("criticality", "UNKNOWN"),
                    "gaps": host_gaps
                })
        return gaps

    def _update_scan_history(self, depth: int, classified: list, commands: list = None):
        """Append a scan-history entry for the current OODA depth.

        Called after the Orient phase so the history always reflects fully-classified host
        state. The entry is later consumed by _build_history_context() to provide the LLM
        with a compressed summary of what was found in previous iterations.

        Args:
            depth: Current loop depth (1-indexed), stored verbatim in the entry.
            classified: List of classified host dicts as returned by _classify_hosts().
            commands: List of nmap command strings executed during this depth.
        """
        self.scan_history.append({
            "depth": depth,
            "hosts": [
                {
                    "ip": h["target"],
                    "type": h.get("type", "Unknown"),
                    "ports": [p["port"] for p in h.get("ports", [])]
                }
                for h in classified
            ],
            "commands": commands or [],
        })

    def _execute_and_merge(self, command: str, inject_vulners: bool = False):
        """Execute an Nmap command and merge parsed TOON hosts into _host_map.

        Accumulates total_packets into self.metrics and silently skips execution when
        command is empty (guards against LLM returning no command). Uses _merge_host()
        so richer port data from later scans overwrites weaker earlier data.

        Args:
            command: Prepared Nmap command string from the Decide phase. Empty string
                     is treated as a no-op with a warning log.
            inject_vulners: Optional flag to inject vulners NSE script (default: False).
        """
        if not command:
            self._log("Act phase received empty command — skipping.", "warning")
            return
        raw_xml, pkts = self.executor.execute(command, inject_vulners=inject_vulners)
        self.metrics["total_packets"] += pkts
        if not raw_xml:
            self._log("Act phase scan produced no output.", "warning")
            return
        for host in self.parser.parse(raw_xml):
            self._merge_host(host)

    def _log(self, msg: str, level: str = "info"):
        """Log and emit to dashboard simultaneously."""
        getattr(self.logger, level)(msg)
        self._emit("log", {"level": level, "message": msg})

    def _run_discovery(self, target: str) -> list:
        """Phase 1: run discovery scan, filter own IPs. Returns live_ips list (empty = abort)."""
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
            return []

        raw_xml, pkts = self.executor.execute(discovery_cmd)
        self.metrics["total_packets"] += pkts
        if not raw_xml:
            self._log("Discovery scan produced no output.", "error")
            return []

        toon_hosts = self.parser.parse(raw_xml)
        if not toon_hosts:
            self._log("No live hosts found. Scan complete.")
            return []

        live_ips = [h['target'] for h in toon_hosts]

        own_ips = self._get_own_ips()
        excluded = [ip for ip in live_ips if ip in own_ips]
        if excluded:
            self._log(f"Excluding own IP(s) from scan: {excluded}")
            live_ips = [ip for ip in live_ips if ip not in own_ips]

        self._log(f"Discovered {len(live_ips)} live hosts: {live_ips}")
        self._emit("hosts_found", {"hosts": live_ips})
        return live_ips

    def _classify_hosts(self, detailed_hosts: list) -> tuple:
        """
        Hybrid classification: static scoring extracts evidence, one LLM call
        classifies all hosts, labels merged before critical_targets is assembled.
        Returns (classified, critical_targets).
        """
        evidence_bundles = []  # list of evidence bundle dicts

        # ── Pass 1: Static scoring + build evidence bundles ─────────────────
        for host in detailed_hosts:
            assessment = self.assessor.assess(host)
            # Set initial labels (may be overwritten by LLM in Pass 2)
            host["criticality"] = assessment["level"]
            host["type"] = assessment["type"]
            host["metrics"] = assessment["reasons"]
            evidence_bundles.append(
                self.assessor.build_evidence_bundle(host, assessment)
            )

        # ── LLM classification call ──────────────────────────────────────────
        self._emit("status", {"message": "Classifying hosts with AI..."})
        llm_results = self.agent.classify_hosts(evidence_bundles)
        if not llm_results:
            self._log("AI classification unavailable — using static labels.", "warning")
        llm_lookup = {r["ip"]: r for r in llm_results}

        # ── Pass 2: Merge LLM labels + emit + assemble critical_targets ──────
        classified = []
        critical_targets = []

        for host in detailed_hosts:
            llm = llm_lookup.get(host["target"])
            if llm:
                llm_type = llm.get("type", host["type"])
                llm_crit = llm.get("criticality", host["criticality"])
                host["type"] = llm_type if llm_type in _VALID_TYPES else host["type"]
                host["criticality"] = llm_crit if llm_crit in _VALID_CRITICALITIES else host["criticality"]
            classified.append(host)

            self._log(
                f"Host {host['target']} → [{host['type']}] ({host['criticality']})"
            )
            self._emit("host_assessed", {
                "ip": host["target"],
                "type": host["type"],
                "criticality": host["criticality"],
                "ports": host["ports"],
                "reasons": host["metrics"],
            })

            if host["criticality"] in ("CRITICAL", "HIGH"):
                critical_targets.append({"ip": host["target"], "type": host["type"]})

        self.metrics["total_hosts"] = len(detailed_hosts)
        self.metrics["critical_hosts"] = len(critical_targets)
        return classified, critical_targets

    def _run_cve_enrichment(self) -> None:
        """CVE enrichment pass. Reassigns self._all_hosts (enrich functions return new lists)."""
        self._log("CVE Enrichment: correlating NSE script output and CPE lookups...")
        self._emit("status", {"phase": "cve_enrichment"})

        self._all_hosts = self.exploit_lookup.enrich_from_nse(self._all_hosts)
        self._all_hosts = self.exploit_lookup.enrich_from_cpe(self._all_hosts)

        for host in self._all_hosts:
            seen = {}  # cve_id -> best entry (highest CVSS)
            for port in host.get("ports", []):
                for exploit in port.get("exploits", []):
                    cve_id = exploit.get("cve", "")
                    if not cve_id:
                        continue
                    if cve_id not in seen or exploit.get("cvss", 0) > seen[cve_id]["cvss"]:
                        seen[cve_id] = {
                            "port": port["port"],
                            "service": port["service"],
                            "cve": cve_id,
                            "cvss": exploit.get("cvss", 0),
                            "source": exploit.get("source", ""),
                        }
            cves = list(seen.values())
            if cves:
                self._emit("cves_found", {"ip": host["target"], "cves": cves})
                self._log(f"  {host['target']}: {len(cves)} CVE(s) found")

    def _generate_report(self, partial: bool = False) -> None:
        """Phase 4: generate AI report, save files, emit metrics and done event.
        partial=True uses degraded messages when called after Phase 2 failure."""
        # Preserve original early-return guard: on the normal (non-partial) path,
        # if there is no host data at all, log and return without writing files.
        if not partial and not self._all_hosts:
            self._log("No host data to report.", "warning")
            return

        if partial:
            self._log("PHASE 4: Final AI Analysis & Report Generation (with partial data)")
        else:
            self._log("PHASE 4: Final AI Analysis & Report Generation")
        self._emit("status", {"phase": "reporting"})

        if self._all_hosts:
            report = self.agent.analyze_results(self._all_hosts)
        else:
            report = (
                "# Reconesis Scan Report\n\n"
                "**No reconnaissance data available** — Port scan phase failed and could not be "
                "recovered. Please check your Groq API key and network connectivity."
            )

        self._emit("report", {"content": report})

        if not partial:
            with open("scan_results.json", "w") as f:
                json.dump(self._all_hosts, f, indent=2)

        with open("scan_report.md", "w") as f:
            f.write(report)

        self.metrics["end_time"] = time.time()

        if partial:
            self._emit("done", {"message": "Reconesis scan completed with errors (see report)."})
            self._log("❌ Reconesis failed to complete full reconnaissance due to Phase 2 failure.")
            print("\n=== SCAN REPORT (INCOMPLETE) ===\n")
            print(report)
        else:
            elapsed = self.metrics["end_time"] - self.metrics["start_time"]
            total_hosts = self.metrics["total_hosts"]
            critical = self.metrics["critical_hosts"]
            if total_hosts > 0:
                self.metrics["time_per_host"] = round(elapsed / total_hosts, 2)
                self.metrics["critical_ratio"] = round((critical / total_hosts) * 100, 1)
            self._emit("metrics", self.metrics)
            self._emit("done", {"message": "Reconesis scan complete."})
            self._log(f"✅ Reconesis complete. {total_hosts} hosts scanned, {critical} critical found.")
            self._log(f"   Time/host: {self.metrics['time_per_host']}s | Depth: {self.metrics['depth']}")
            print("\n=== FINAL REPORT ===\n")
            print(report)

        self.logger.info("Reconesis Task Completed.")

    def _mini_loop(self, context: dict, inject_vulners: bool = False) -> list:
        """Drive one depth's scan cycle. Calls decide_for_depth() up to MAX_SUB_ITERATIONS
        times, merging results after each command. Exits early on continue:false, hash
        saturation, or API/parse error. inject_vulners is forwarded to _execute_and_merge().

        Computes gap_map from _compute_gaps() before each decide_for_depth() call and
        injects it into context["gap_map"] so GroqAgent can call render_with_gaps()
        without accessing engine state directly.

        Returns:
            List of nmap command strings that were executed during this depth.
        """
        depth = context.get("depth", 0)
        prev_hash = ""
        commands_run: list = []
        scanned_ports: set = set()

        for _ in range(Config.MAX_SUB_ITERATIONS):
            # Compute gap_map on the engine side (has access to _compute_gaps and _host_map)
            gap_report = self._compute_gaps()
            context["gap_map"] = {g["ip"]: g["gaps"] for g in gap_report}

            # Inject scanned ports into context for depth1 so LLM avoids duplicates
            if depth == 1 and scanned_ports:
                context["scanned_ports"] = scanned_ports

            try:
                decision = self.agent.decide_for_depth(context)
            except (ReconesisAPIError, ReconesisParseError) as e:
                self._log(f"decide_for_depth error in depth {depth}: {e}", "warning")
                break

            if not decision or not decision.get("command"):
                break

            cmd = decision["command"]
            commands_run.append(cmd)

            # Track scanned ports in depth1 to inform subsequent iterations
            if depth == 1:
                scanned_ports.update(self._extract_port_set(cmd))

            self._execute_and_merge(cmd, inject_vulners=inject_vulners)

            # Hash is computed before stub seeding so new_targets additions don't
            # artificially advance the hash and prevent saturation detection.
            new_hash = self.parser.compute_hash(list(self._host_map.values()))

            # Depth1: ignore new_targets to prevent LLM from hallucinating adjacent subnets
            if depth != 1:
                new_targets = [t for t in decision.get("new_targets", []) if t not in self._host_map]
                for t in new_targets:
                    self._host_map[t] = {
                        "target": t, "status": "up",
                        "os": {"name": "unknown", "accuracy": 0},
                        "ports": [], "criticality": "UNKNOWN", "type": "Unknown",
                    }
                if new_targets:
                    self._log(f"Depth {depth}: seeded {len(new_targets)} new target(s): {new_targets}")

            if not decision.get("continue", True):
                self._log(f"Depth {depth}: LLM signalled complete.")
                break

            if new_hash == prev_hash:
                self._log(f"Depth {depth}: hash saturation — no new information.")
                break
            prev_hash = new_hash

            context["scan_history"] = self.scan_history
            context["hosts"] = list(self._host_map.values())

        return commands_run

    def _run_depth1_mapping(self, live_ips: list) -> list:
        """Depth 1: broad network mapping over all discovered hosts. Returns commands executed."""
        self._log("DEPTH 1: Network Mapping — building complete network picture")
        self._emit("status", {"phase": "depth1_mapping"})
        context = {
            "depth": 1,
            "depth_purpose": _DEPTH1_PURPOSE,
            "target_hosts": list(self._host_map.values()),
            "hosts": list(self._host_map.values()),
            "scan_history": self.scan_history,
        }
        return self._mini_loop(context, inject_vulners=False)

    def _run_depth2_deep_dive(self, critical_high_hosts: list) -> list:
        """Depth 2: deep fingerprint on CRITICAL/HIGH hosts only. Returns commands executed."""
        self._log(f"DEPTH 2: Deep Fingerprint — {len(critical_high_hosts)} CRITICAL/HIGH assets")
        self._emit("status", {"phase": "depth2_deep_dive", "targets": critical_high_hosts})
        target_hosts = [self._host_map[t["ip"]] for t in critical_high_hosts if t["ip"] in self._host_map]
        context = {
            "depth": 2,
            "depth_purpose": _DEPTH2_PURPOSE,
            "target_hosts": target_hosts,
            "hosts": list(self._host_map.values()),
            "scan_history": self.scan_history,
        }
        return self._mini_loop(context, inject_vulners=False)

    def _run_depth3_deepest(self, critical_high_hosts: list) -> list:
        """Depth 3: vulnerability enumeration on CRITICAL/HIGH hosts. Returns commands executed."""
        self._log(f"DEPTH 3: Vulnerability Enumeration — {len(critical_high_hosts)} targets")
        self._emit("status", {"phase": "depth3_deepest", "targets": critical_high_hosts})
        target_hosts = [self._host_map[t["ip"]] for t in critical_high_hosts if t["ip"] in self._host_map]
        context = {
            "depth": 3,
            "depth_purpose": _DEPTH3_PURPOSE,
            "target_hosts": target_hosts,
            "hosts": list(self._host_map.values()),
            "scan_history": self.scan_history,
        }
        return self._mini_loop(context, inject_vulners=True)

    def start_scan(self, target: str):
        self.metrics["start_time"] = time.time()
        self._host_map = {}
        self._log(f"🚀 Starting Reconesis on target: {target}")
        self._emit("status", {"phase": "discovery", "target": target})

        live_ips = self._run_discovery(target)
        if not live_ips:
            return

        for ip in live_ips:
            if ip not in self._host_map:
                self._host_map[ip] = {
                    "target": ip, "status": "up",
                    "os": {"name": "unknown", "accuracy": 0},
                    "ports": [], "criticality": "UNKNOWN", "type": "Unknown",
                }

        # Depth 1: broad network mapping
        commands1 = self._run_depth1_mapping(live_ips)
        self.metrics["depth"] = 1

        # Hybrid classification: static scorer evidence + LLM final labels
        classified, critical_high_hosts = self._classify_hosts(list(self._host_map.values()))
        for host in classified:
            ip = host["target"]
            if ip in self._host_map:
                self._host_map[ip]["type"] = host["type"]
                self._host_map[ip]["criticality"] = host["criticality"]
        self.metrics["total_hosts"] = len(classified)
        self.metrics["critical_hosts"] = len(critical_high_hosts)
        self._update_scan_history(1, classified, commands1)

        # Depth 2: deep fingerprint (CRITICAL/HIGH only)
        if critical_high_hosts:
            commands2 = self._run_depth2_deep_dive(critical_high_hosts)
            self.metrics["depth"] = 2
            self._update_scan_history(2, list(self._host_map.values()), commands2)

            # Depth 3: vulnerability enumeration (same targets)
            commands3 = self._run_depth3_deepest(critical_high_hosts)
            self.metrics["depth"] = 3
            self._update_scan_history(3, list(self._host_map.values()), commands3)

        self._run_cve_enrichment()
        self._generate_report()
