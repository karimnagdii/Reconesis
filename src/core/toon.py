
import xml.etree.ElementTree as ET
import json
import logging


class TOONParser:
    def __init__(self):
        self.logger = logging.getLogger("TOONParser")

    def parse(self, nmap_xml_content):
        """
        Parses Nmap XML content and returns a list of TOON objects (one per host).
        TOON = Target-Oriented Object Notation (proposal §4.2)
        """
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

                ports.append({
                    "port": port_id,
                    "protocol": protocol,
                    "service": service_name,
                    "product": product,
                    "version": version,
                    "auth_required": auth_required
                })

        return {
            "target": ip_address,
            "status": "up",
            "os": {"name": os_name, "accuracy": os_accuracy},
            "ports": ports,
            "criticality": "UNKNOWN"   # Set by CriticalityAssessor
        }

    def to_json(self, toon_objects):
        return json.dumps(toon_objects, indent=2)

    def compute_hash(self, toon_objects: list) -> str:
        """
        Computes a stable hash of the TOON data for hash-saturation detection.
        Proposal §4.3.4: stop if subsequent scans produce identical hashes.
        """
        import hashlib
        serialized = json.dumps(toon_objects, sort_keys=True)
        return hashlib.sha256(serialized.encode()).hexdigest()
