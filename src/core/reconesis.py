
import logging
import json
import time
import hashlib
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
        self.executor = NmapExecutor()
        self.agent = GroqAgent()
        self.assessor = CriticalityAssessor()
        self.exploit_lookup = ExploitLookup()
        self.scan_history = []

        # Dashboard event stream hook
        self._emit = event_callback if event_callback else lambda t, d: None

        # Evaluation metrics (proposal §5)
        self.metrics = {
            "start_time": None,
            "end_time": None,
            "depth": 0,
            "total_hosts": 0,
            "critical_hosts": 0,
            "total_packets": 0,
            "time_per_host": 0.0,
            "decision_accuracy": 0.0
        }

    def _log(self, msg: str, level: str = "info"):
        """Log and emit to dashboard simultaneously."""
        getattr(self.logger, level)(msg)
        self._emit("log", {"level": level, "message": msg})

    def _compute_accuracy(self, hosts: list) -> dict:
        """
        Compute decision accuracy against ground truth if available (proposal §5).
        Uses binary classification: is the host critical/high vs medium/low?
        Falls back to ratio metric when ground truth is not available.
        """
        gt = Config.GROUND_TRUTH
        scanned_ips = {h.get("target") for h in hosts}

        # Check if any scanned IPs match ground truth entries
        matching_ips = scanned_ips & set(gt.keys())
        if not matching_ips:
            # Fallback: ratio metric (no ground truth for this network)
            total = self.metrics["total_hosts"]
            critical = self.metrics["critical_hosts"]
            ratio = round((critical / total) * 100, 1) if total > 0 else 0.0
            self._log(f"No ground truth available — using ratio metric: {ratio}%")
            return {"accuracy": ratio, "method": "ratio"}

        tp = fp = tn = fn = 0
        for host in hosts:
            ip = host.get("target")
            if ip not in gt:
                continue
            actual_is_critical = host.get("criticality", "LOW") in ("CRITICAL", "HIGH")
            expected_is_critical = gt[ip]["criticality"] in ("CRITICAL", "HIGH")

            if actual_is_critical and expected_is_critical:
                tp += 1
            elif actual_is_critical and not expected_is_critical:
                fp += 1
            elif not actual_is_critical and expected_is_critical:
                fn += 1
            else:
                tn += 1

        total = tp + fp + tn + fn
        accuracy = round(((tp + tn) / total) * 100, 1) if total > 0 else 0.0
        precision = round((tp / (tp + fp)) * 100, 1) if (tp + fp) > 0 else 0.0
        recall = round((tp / (tp + fn)) * 100, 1) if (tp + fn) > 0 else 0.0
        f1 = round(2 * (precision * recall) / (precision + recall), 1) if (precision + recall) > 0 else 0.0

        self._log(f"Decision accuracy (ground truth): {accuracy}% | P={precision}% R={recall}% F1={f1}%")
        return {
            "accuracy": accuracy,
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "method": "ground_truth"
        }

    def start_scan(self, target: str):
        self.metrics["start_time"] = time.time()
        self._log(f"🚀 Starting Reconesis on target: {target}")
        self._emit("status", {"phase": "discovery", "target": target})

        seen_hashes = set()          # Information-saturation termination (proposal §4.3.4)
        depth = 0
        live_ips = []
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
                self._log(f"Discovered {len(live_ips)} live hosts: {live_ips}")
                self._emit("hosts_found", {"hosts": live_ips})

                # OODA feedback: record discovery findings (proposal §4.1)
                self.scan_history.append({
                    "phase": "discovery",
                    "depth": depth,
                    "live_hosts": live_ips,
                    "host_count": len(live_ips)
                })

            # -----------------------------------------------------------
            # PHASE 2: PORT SCAN & ASSET CLASSIFICATION
            # -----------------------------------------------------------
            self._log("PHASE 2: SCOUT MODE — Port Scan & Asset Classification")
            self._emit("status", {"phase": "assessment"})

            port_scan_cmd = self.agent.generate_strategy({
                "phase": "port_scan",
                "live_hosts": live_ips,
                "previous_findings": self.scan_history
            })
            self._log(f"Agent command: {port_scan_cmd}")

            if not port_scan_cmd:
                self._log("Agent returned no port scan command — stopping loop.", "warning")
                break

            raw_xml_detailed, pkts = self.executor.execute(port_scan_cmd)
            self.metrics["total_packets"] += pkts
            if not raw_xml_detailed:
                self._log("Port scan produced no output — stopping loop.", "warning")
                break

            detailed_hosts = self.parser.parse(raw_xml_detailed)

            # --- Information Saturation Check (proposal §4.3.4) ---
            current_hash = self.parser.compute_hash(detailed_hosts)
            if current_hash in seen_hashes:
                self._log("Information saturation detected — no new information. Stopping loop.")
                all_detailed_hosts = detailed_hosts  # Use last data
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

            # OODA feedback: record assessment findings (proposal §4.1)
            self.scan_history.append({
                "phase": "assessment",
                "depth": depth,
                "hosts": [{
                    "ip": h["target"],
                    "type": h.get("type"),
                    "criticality": h.get("criticality"),
                    "ports": [p["port"] for p in h.get("ports", [])]
                } for h in detailed_hosts]
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

            hunter_xml, pkts = self.executor.execute(hunter_cmd)
            self.metrics["total_packets"] += pkts
            if hunter_xml:
                hunter_hosts = self.parser.parse(hunter_xml)
                # Merge hunter findings into our host records
                hunter_map = {h['target']: h for h in hunter_hosts}
                for host in all_detailed_hosts:
                    if host['target'] in hunter_map:
                        # Enrich existing record with new port/version data
                        new_ports = hunter_map[host['target']].get('ports', [])
                        existing_ports = {p['port'] for p in host.get('ports', [])}
                        for p in new_ports:
                            if p['port'] not in existing_ports:
                                host['ports'].append(p)
                        self._emit("host_enriched", {
                            "ip": host['target'],
                            "ports": host['ports']
                        })
                # OODA feedback: record hunter findings (proposal §4.1)
                self.scan_history.append({
                    "phase": "hunter",
                    "depth": depth,
                    "enriched_hosts": [{
                        "ip": h["target"],
                        "port_count": len(h.get("ports", []))
                    } for h in hunter_hosts]
                })
            else:
                self._log("Hunter scan produced no output.", "warning")

            # --- Exploit/CVE Correlation ---
            self._log("Running exploit/CVE correlation on discovered services...")
            all_detailed_hosts = self.exploit_lookup.enrich_from_nse(all_detailed_hosts)
            all_detailed_hosts = self.exploit_lookup.enrich_from_cpe(all_detailed_hosts)

            # Emit exploit data per host to dashboard
            for host in all_detailed_hosts:
                host_exploits = []
                for port in host.get("ports", []):
                    for exploit in port.get("exploits", []):
                        host_exploits.append({
                            "port": port["port"],
                            "service": port.get("service", ""),
                            **exploit
                        })
                if host_exploits:
                    self._emit("host_exploits", {
                        "ip": host["target"],
                        "exploits": host_exploits
                    })

            # Hunter complete for this depth. Loop continues to next depth level
            # where Assessment re-runs with OODA context. Information saturation
            # (line above) will terminate if no new data is discovered.
            self._log(f"Hunter mode complete for depth {depth}. Continuing to next iteration...")

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
            # Decision accuracy: real accuracy against ground truth when available (proposal §5)
            accuracy_data = self._compute_accuracy(all_detailed_hosts)
            self.metrics["decision_accuracy"] = accuracy_data["accuracy"]
            self.metrics["accuracy_details"] = accuracy_data

        self._emit("metrics", self.metrics)
        self._emit("done", {"message": "Reconesis scan complete."})
        self._log(f"✅ Reconesis complete. {total_hosts} hosts scanned, {critical} critical found.")
        self._log(f"   Time/host: {self.metrics['time_per_host']}s | Depth: {depth}")

        print("\n=== FINAL REPORT ===\n")
        print(report)
        self.logger.info("Reconesis Task Completed.")
