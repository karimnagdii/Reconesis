
import xml.etree.ElementTree as ET
import json
import re
import logging


class TOONParser:
    def __init__(self):
        self.logger = logging.getLogger("TOONParser")

    def parse(self, raw_output: str) -> list:
        """
        Auto-detects Nmap output format (XML or Greppable) and parses accordingly.
        Returns a list of TOON objects (one per host).
        TOON = Target-Oriented Object Notation (proposal §4.2)
        Supports XML (-oX) and Greppable (-oG) formats (proposal §2, Contribution #2).
        """
        raw_output = raw_output.strip()
        if raw_output.startswith("<?xml") or raw_output.startswith("<nmaprun"):
            return self._parse_xml(raw_output)
        elif raw_output.startswith("# Nmap") or "Host:" in raw_output:
            self.logger.warning(
                "Greppable format detected — reduced data fidelity "
                "(no OS detection, limited version info, no NSE scripts)."
            )
            return self.parse_greppable(raw_output)
        else:
            # Try XML first, fall back to greppable
            try:
                return self._parse_xml(raw_output)
            except ET.ParseError:
                self.logger.warning("XML parse failed, attempting greppable format fallback.")
                return self.parse_greppable(raw_output)

    def _parse_xml(self, nmap_xml_content: str) -> list:
        """Parses Nmap XML content into TOON objects."""
        try:
            root = ET.fromstring(nmap_xml_content)
            toon_objects = []

            for host in root.findall('host'):
                toon_obj = self._parse_host(host)
                if toon_obj:
                    toon_objects.append(toon_obj)

            return toon_objects
        except ET.ParseError as e:
            self.logger.error(f"Failed to parse Nmap XML: {e}")
            return []

    def _parse_host(self, host_element):
        """
        Parses a single <host> element into a TOON dictionary.
        """
        # Only keep live hosts
        status_elem = host_element.find('status')
        if status_elem is None or status_elem.get('state') != 'up':
            return None

        address_elem = host_element.find('address')
        ip_address = address_elem.get('addr') if address_elem is not None else "unknown"

        # OS detection
        os_name = "unknown"
        os_accuracy = 0
        os_elem = host_element.find('os')
        if os_elem:
            os_match = os_elem.find('osmatch')
            if os_match:
                os_name = os_match.get('name', 'unknown')
                os_accuracy = int(os_match.get('accuracy', 0))

        # Port parsing — includes auth_required field (proposal §4.2 TOON structure)
        ports = []
        ports_elem = host_element.find('ports')
        if ports_elem:
            for port_elem in ports_elem.findall('port'):
                state_elem = port_elem.find('state')
                if state_elem is None or state_elem.get('state') != 'open':
                    continue

                port_id = int(port_elem.get('portid'))
                protocol = port_elem.get('protocol')

                service_elem = port_elem.find('service')
                service_name = service_elem.get('name', 'unknown') if service_elem is not None else 'unknown'
                product = service_elem.get('product', '') if service_elem is not None else ''
                version = service_elem.get('version', '') if service_elem is not None else ''
                extra_info = service_elem.get('extrainfo', '') if service_elem is not None else ''
                tunnel = service_elem.get('tunnel', '') if service_elem is not None else ''

                # Infer auth_required: SSL tunneled services or known auth services
                auth_required = (
                    tunnel == 'ssl'
                    or service_name in {'ssh', 'rdp', 'vnc', 'ftp', 'smtp', 'imap', 'pop3'}
                    or 'auth' in extra_info.lower()
                    or 'tls' in extra_info.lower()
                )

                # Parse NSE script results (for exploit correlation — Issue 11)
                scripts = []
                for script_elem in port_elem.findall('script'):
                    scripts.append({
                        "id": script_elem.get("id", ""),
                        "output": script_elem.get("output", "")
                    })

                ports.append({
                    "port": port_id,
                    "protocol": protocol,
                    "service": service_name,
                    "product": product,
                    "version": version,
                    "auth_required": auth_required,
                    "scripts": scripts
                })

        return {
            "target": ip_address,
            "status": "up",
            "os": {"name": os_name, "accuracy": os_accuracy},
            "ports": ports,
            "criticality": "UNKNOWN"   # Set by CriticalityAssessor
        }

    def parse_greppable(self, greppable_output: str) -> list:
        """
        Parses Nmap greppable (-oG) format into TOON objects.
        Fallback parser when XML is unavailable. (Proposal §2, Contribution #2)

        Greppable format lines look like:
            Host: 192.168.1.1 ()	Ports: 22/open/tcp//ssh///, 80/open/tcp//http///
        """
        toon_objects = []
        for line in greppable_output.strip().split("\n"):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "Status: Up" not in line and "Ports:" not in line:
                continue

            # Extract IP: "Host: 192.168.1.1 (hostname)"
            host_match = re.match(r'Host:\s+(\S+)', line)
            if not host_match:
                continue
            ip = host_match.group(1)

            ports = []
            # Extract ports: "Ports: 22/open/tcp//ssh///, 80/open/tcp//http///"
            ports_match = re.search(r'Ports:\s+(.+?)(?:\t|$)', line)
            if ports_match:
                for port_entry in ports_match.group(1).split(","):
                    parts = port_entry.strip().split("/")
                    if len(parts) >= 5 and parts[1] == "open":
                        service = parts[4] if len(parts) > 4 else "unknown"
                        product = parts[6] if len(parts) > 6 else ""
                        ports.append({
                            "port": int(parts[0]),
                            "protocol": parts[2] if len(parts) > 2 else "tcp",
                            "service": service or "unknown",
                            "product": product,
                            "version": "",
                            "auth_required": service in (
                                "ssh", "rdp", "vnc", "ftp", "smtp", "imap", "pop3"
                            ),
                            "scripts": []
                        })

            toon_objects.append({
                "target": ip,
                "status": "up",
                "os": {"name": "unknown", "accuracy": 0},
                "ports": ports,
                "criticality": "UNKNOWN"
            })
        return toon_objects

    def to_json(self, toon_objects):
        return json.dumps(toon_objects, indent=2)

    def compute_hash(self, toon_objects: list) -> str:
        """
        Computes a stable hash of the TOON data for information-saturation detection.
        Proposal §4.3.4: stop if subsequent scans produce identical hashes.
        """
        import hashlib
        serialized = json.dumps(toon_objects, sort_keys=True)
        return hashlib.sha256(serialized.encode()).hexdigest()
