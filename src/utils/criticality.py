
from src.utils.config import Config


class CriticalityAssessor:
    """
    Multi-signal criticality assessment engine.

    Proposal §4.3.2 defines four critical asset categories:
      - Routers:   Ports 22+23, 179 (BGP), SNMP 161; OS: IOS, RouterOS, JunOS
      - Firewalls: Ports 22+443, 8443; OS: FortiOS, PaloAlto, Checkpoint, ASA
      - Mail:      Ports 25, 110, 143, 465, 587, 993, 995; services: smtp/imap/pop3
      - Database:  Ports 3306, 5432, 1433, 1521, 27017, 6379; services: mysql/pgsql/mssql

    Instead of an elif chain (only first match wins), this version:
      1. Scores EVERY category independently using weighted signals
      2. Combines port evidence + service name + product string + OS fingerprint
      3. Picks the highest-scoring category as the winner
      4. A host can accumulate evidence from ALL signal types
    """

    # ── Signal Definitions ──────────────────────────────────

    # Each category has weighted signals:
    #   port_exact:    exact port matches              (+2 each)
    #   port_combo:    port combinations               (+3 if combo present)
    #   services:      service name exact matches      (+3 each)
    #   products:      substrings in product field      (+3 each)
    #   os_keywords:   substrings in OS fingerprint    (+4 each)

    PROFILES = {
        "Database Server": {
            "port_exact":  {3306, 5432, 1433, 1521, 27017, 6379, 5984, 9200, 9300},
            "port_combo":  [],
            "services":    {"mysql", "postgresql", "ms-sql-s", "mssql", "oracle-tns",
                            "mongodb", "redis", "couchdb", "elasticsearch", "cassandra",
                            "mariadb"},
            "products":    ["mysql", "mariadb", "postgresql", "postgres", "microsoft sql",
                            "oracle", "mongodb", "redis", "couchdb", "elasticsearch",
                            "cassandra"],
            "os_keywords": [],  # DBs run on generic OSes
        },
        "Mail Server": {
            "port_exact":  {25, 110, 143, 465, 587, 993, 995, 2525},
            "port_combo":  [],
            "services":    {"smtp", "pop3", "pop3s", "imap", "imaps", "submission",
                            "smtps"},
            "products":    ["postfix", "exim", "sendmail", "dovecot", "exchange",
                            "hmail", "zimbra", "roundcube", "courier", "qmail",
                            "microsoft esmtp"],
            "os_keywords": [],  # Mail servers run on generic OSes
        },
        "Firewall": {
            "port_exact":  {8443, 541, 8080},
            "port_combo":  [
                {22, 443},        # SSH + HTTPS management (proposal §4.3.2)
                {443, 8443},      # Dual HTTPS management interfaces
            ],
            "services":    set(),
            "products":    ["fortios", "fortigate", "palo alto", "panos",
                            "checkpoint", "cisco asa", "adaptive security",
                            "sophos", "watchguard", "sonicwall", "pfense",
                            "opnsense", "juniper srx", "firepower"],
            "os_keywords": ["fortinet", "fortigate", "fortios",
                            "palo alto", "paloalto", "pan-os",
                            "checkpoint", "gaia",
                            "cisco asa", "adaptive security", "firepower",
                            "sophos", "watchguard", "sonicwall",
                            "juniper srx", "pfsense", "opnsense"],
        },
        "Router": {
            "port_exact":  {179, 161, 162, 2601, 2602},  # BGP, SNMP, Zebra
            "port_combo":  [
                {22, 23},         # SSH + Telnet (classic router combo, proposal §4.3.2)
                {22, 23, 161},    # SSH + Telnet + SNMP (strong router signal)
            ],
            "services":    {"bgp", "snmp", "telnet"},
            "products":    ["cisco ios", "routeros", "mikrotik", "junos", "juniper",
                            "arista eos", "vyos", "vyatta", "quagga", "frr",
                            "huawei vrp", "nokia sros", "bird"],
            "os_keywords": ["cisco ios", "ios-xe", "ios xe", "ios xr",
                            "routeros", "mikrotik",
                            "junos", "juniper",
                            "arista eos", "arista",
                            "vyos", "vyatta",
                            "huawei vrp",
                            "nokia sros"],
        },
    }

    # ── Point Weights ──────────────────────────────────────
    W_PORT_EXACT   = 2     # Each matching port
    W_PORT_COMBO   = 3     # Each matching port combo
    W_SERVICE      = 3     # Each matching service name
    W_PRODUCT      = 3     # Each matching product substring
    W_OS           = 4     # Each matching OS keyword (strongest signal)

    # Thresholds
    CRITICAL_THRESHOLD = 4     # Score >= 4 → CRITICAL
    HIGH_THRESHOLD     = 2     # Score >= 2 → HIGH

    def __init__(self):
        self.critical_ports = Config.CRITICAL_PORTS

    def assess(self, toon_host: dict) -> dict:
        """
        Score the host against ALL four asset categories independently,
        then pick the highest-scoring one.
        Returns: { 'level': str, 'type': str, 'reasons': list, 'scores': dict }
        """
        # ── Extract all available signals from the TOON host ──
        ports = toon_host.get("ports", [])
        port_numbers = {p.get("port") for p in ports}
        services = {p.get("service", "").lower() for p in ports}
        services.discard("")

        # Combine product + version into one searchable string per port
        products_per_port = []
        for p in ports:
            prod = (p.get("product", "") + " " + p.get("version", "")).strip().lower()
            if prod:
                products_per_port.append(prod)
        all_products = " | ".join(products_per_port)

        os_name = toon_host.get("os", {}).get("name", "").lower()
        os_accuracy = toon_host.get("os", {}).get("accuracy", 0)

        # ── Score each category ──
        category_scores = {}
        category_reasons = {}

        for category, profile in self.PROFILES.items():
            score = 0
            reasons = []

            # 1. Exact port matches
            matched_ports = port_numbers & profile["port_exact"]
            if matched_ports:
                pts = self.W_PORT_EXACT * len(matched_ports)
                score += pts
                reasons.append(f"Ports {sorted(matched_ports)} matched (+{pts})")

            # 2. Port combinations (e.g. SSH+Telnet = router signal)
            for combo in profile.get("port_combo", []):
                if combo.issubset(port_numbers):
                    score += self.W_PORT_COMBO
                    reasons.append(f"Port combo {sorted(combo)} present (+{self.W_PORT_COMBO})")

            # 3. Service names (nmap service field)
            matched_services = services & profile["services"]
            if matched_services:
                pts = self.W_SERVICE * len(matched_services)
                score += pts
                reasons.append(f"Services {sorted(matched_services)} matched (+{pts})")

            # 4. Product strings (substring match in product+version)
            for keyword in profile["products"]:
                if keyword in all_products:
                    score += self.W_PRODUCT
                    reasons.append(f"Product '{keyword}' found (+{self.W_PRODUCT})")

            # 5. OS fingerprint keywords (strongest signal)
            if os_name and os_name != "unknown":
                for keyword in profile["os_keywords"]:
                    if keyword in os_name:
                        # Weight OS signal by accuracy confidence
                        weight = self.W_OS
                        if os_accuracy >= 90:
                            weight += 1  # Bonus for high-confidence OS match
                        score += weight
                        reasons.append(
                            f"OS '{keyword}' matched (accuracy {os_accuracy}%) (+{weight})"
                        )
                        break  # One OS match per category is enough

            category_scores[category] = score
            category_reasons[category] = reasons

        # ── Pick the winner ──
        best_category = max(category_scores, key=category_scores.get)
        best_score = category_scores[best_category]

        if best_score >= self.CRITICAL_THRESHOLD:
            level = "CRITICAL"
        elif best_score >= self.HIGH_THRESHOLD:
            level = "HIGH"
        elif best_score > 0:
            level = "MEDIUM"
        else:
            level = "LOW"

        # Fallback: if no category scored, check for generic high-value (web server)
        if best_score == 0:
            if 22 in port_numbers and (80 in port_numbers or 443 in port_numbers):
                best_category = "Web Server/Admin Console"
                level = "MEDIUM"
                category_reasons[best_category] = ["SSH with web interface detected"]
                best_score = 1
            else:
                best_category = "Generic Host"
                category_reasons[best_category] = []

        return {
            "level": level,
            "type": best_category,
            "reasons": category_reasons.get(best_category, []),
            "scores": category_scores    # Expose all scores for debugging / dashboard
        }
