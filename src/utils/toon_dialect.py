from src.utils.criticality import CriticalityAssessor

_TYPE_ALIAS = {
    "Database Server":         "D",
    "Mail Server":             "M",
    "Router":                  "R",
    "Firewall":                "F",
    "Active Directory / LDAP": "A",
    "Jump Host":               "J",
    "Web Server":              "W",
    "Application Server":      "S",
    "IoT Camera":              "I",
    "NAS Appliance":           "N",
    "Windows File Server":     "X",
    "DNS Server":              "Z",
    "Generic Host":            "G",
}

_CRIT_ALIAS = {
    "CRITICAL": "C",
    "HIGH":     "H",
    "MEDIUM":   "M",
    "LOW":      "L",
}

_SOURCE_CODE = {
    "nvd":     "n",
    "vulners": "v",
    "circl":   "c",
}

_CRIT_THRESHOLD  = CriticalityAssessor.CRITICAL_THRESHOLD  # used by serialize_classify
_HIGH_THRESHOLD  = CriticalityAssessor.HIGH_THRESHOLD       # used by serialize_classify


class ToonDialect:

    @staticmethod
    def serialize_report(toon_data: list) -> str:
        """
        Serialize fully-classified TOON list to Absolute Zero dialect for report calls.
        Precondition: each host has host["type"] and host["criticality"] set by
        _classify_hosts() in reconesis.py. Do NOT call on raw unclassified TOON.
        """
        blocks = []
        for host in toon_data:
            type_alias = _TYPE_ALIAS.get(host.get("type", "Generic Host"), "G")
            crit       = host.get("criticality", "LOW")
            crit_alias = _CRIT_ALIAS.get(crit, "L")

            os_name = host.get("os", {}).get("name", "")
            os_part = ""
            if os_name and os_name.lower() not in ("unknown", "none", ""):
                os_part = " " + os_name.replace(" ", "-")

            if crit not in ("CRITICAL", "HIGH"):
                blocks.append(f"{host['target']} {type_alias} {crit_alias}")
                continue

            line1 = f"{host['target']} {type_alias} {crit_alias}{os_part}"

            lines = [line1]
            for p in host.get("ports", []):
                port_str = ToonDialect._format_port_report(p)
                lines.append(" " + port_str)

            blocks.append("\n".join(lines))

        return "\n\n".join(blocks)

    @staticmethod
    def _format_port_report(p: dict) -> str:
        port_num = p["port"]
        proto    = p.get("protocol", "tcp")
        auth     = p.get("auth_required", False)
        service  = p.get("service", "")
        product  = p.get("product", "")
        version  = p.get("version", "")

        port_field = f"u:{port_num}" if proto == "udp" else str(port_num)
        if auth:
            port_field += "*"

        prod_field = ""
        if product or version:
            prod_name = product.replace(" ", "-") if product else ""
            if prod_name and version:
                prod_field = f" {prod_name}/{version}"
            elif prod_name:
                prod_field = f" {prod_name}"
            elif version:
                prod_field = f" /{version}"

        svc_field = f" {service}" if service else ""

        # Exploits: cap to top 5 by CVSS descending
        exploits = sorted(
            p.get("exploits", []),
            key=lambda e: e.get("cvss", 0),
            reverse=True
        )[:5]

        exploit_field = ""
        if exploits:
            parts = []
            for e in exploits:
                cve_id = e.get("cve", "").replace("CVE-", "")
                cvss   = e.get("cvss", 0)
                src    = _SOURCE_CODE.get(e.get("source", ""), e.get("source", ""))
                parts.append(f"{cve_id}:{cvss}:{src}")
            exploit_field = " [" + " ".join(parts) + "]"

        return f"{port_field}{svc_field}{prod_field}{exploit_field}"

    @staticmethod
    def serialize_classify(evidence_bundles: list) -> str:
        """
        Serialize evidence bundles to dialect for classify_hosts() call.
        Type/Criticality shown are static scorer guesses for LLM to verify.
        No auth_required or exploits in bundles — omit * and [].
        """
        blocks = []
        for bundle in evidence_bundles:
            static     = bundle.get("static", {})
            top_type   = static.get("top_type", "Generic Host")
            top_score  = static.get("top_score", 0)
            runner     = static.get("runner_up", {})
            runner_type  = runner.get("type", "Generic Host")
            runner_score = runner.get("score", 0)

            type_alias   = _TYPE_ALIAS.get(top_type, "G")
            runner_alias = _TYPE_ALIAS.get(runner_type, "G")

            if top_score >= _CRIT_THRESHOLD:
                crit_alias = "C"
            elif top_score >= _HIGH_THRESHOLD:
                crit_alias = "H"
            elif top_score > 0:
                crit_alias = "M"
            else:
                crit_alias = "L"

            os_dict = bundle.get("os")
            os_part = ""
            if os_dict and os_dict.get("name"):
                os_name = os_dict["name"]
                if os_name.lower() not in ("unknown", "none", ""):
                    os_part = " " + os_name.replace(" ", "-")

            line1  = f"{bundle['ip']} {type_alias} {crit_alias}{os_part}"
            m_line = f" M: {type_alias}:{top_score}>{runner_alias}:{runner_score}"

            port_lines = []
            for p in bundle.get("ports", []):
                port_num = p["port"]
                service  = p.get("service", "")
                product  = p.get("product", "").replace(" ", "-")
                version  = p.get("version", "")

                prod_field = ""
                if product or version:
                    if product and version:
                        prod_field = f" {product}/{version}"
                    elif product:
                        prod_field = f" {product}"
                    else:
                        prod_field = f" /{version}"

                svc_field = f" {service}" if service else ""
                port_lines.append(f" {port_num}{svc_field}{prod_field}")

            block_lines = [line1, m_line] + port_lines
            blocks.append("\n".join(block_lines))

        return "\n\n".join(blocks)

    @staticmethod
    def compress_history(scan_history: list) -> str:
        """
        Compress scan history to dialect. Takes FULL list — caps to last 2 internally.
        Prepends inline decoder header for hunter/scout prompts that lack _DIALECT_RING.
        """
        header = (
            "History (T/C aliases: D=Database M=Mail R=Router F=Firewall "
            "A=AD/LDAP J=Jump W=Web S=AppServer I=IoT N=NAS X=WinFS Z=DNS G=Generic "
            "| C=CRITICAL H=HIGH M=MEDIUM L=LOW):\n"
        )

        recent = scan_history[-2:] if len(scan_history) > 2 else scan_history
        if not recent:
            return header.rstrip()

        depth_lines = []
        for entry in recent:
            n     = entry["depth"]
            hosts = entry.get("hosts", [])
            host_parts = []
            for h in hosts:
                t_alias = _TYPE_ALIAS.get(h.get("type", "Generic Host"), "G")
                c_alias = _CRIT_ALIAS.get(h.get("criticality", "LOW"), "L")
                ports   = ",".join(str(p) for p in h.get("ports", []))
                host_parts.append(f"{h['ip']}/{t_alias}/{c_alias}/{ports}")
            depth_lines.append(f"d{n}: " + " | ".join(host_parts))

        return header + "\n".join(depth_lines)

    @staticmethod
    def render_with_gaps(hosts: list, gap_map: dict) -> str:
        """Render all hosts in TOON with ? (unknown) and ! (no scripts) gap markers.
        gap_map: {ip: [gap_string, ...]} from _compute_gaps() output."""
        if not hosts:
            return ""
        blocks = []
        for host in hosts:
            ip = host["target"]
            gaps = gap_map.get(ip, [])
            type_alias = _TYPE_ALIAS.get(host.get("type", "Generic Host"), "G")
            crit_alias = _CRIT_ALIAS.get(host.get("criticality", "LOW"), "L")

            os_name = host.get("os", {}).get("name", "")
            if "os_unknown" in gaps:
                os_part = " ?"
            elif os_name and os_name.lower() not in ("unknown", "none", ""):
                os_part = " " + os_name.replace(" ", "-")
            else:
                os_part = ""

            lines = [f"{ip} {type_alias} {crit_alias}{os_part}"]

            for p in host.get("ports", []):
                port_num = p["port"]
                svc = p.get("service", "")
                proto = p.get("protocol", "tcp")
                auth = p.get("auth_required", False)

                port_field = f"u:{port_num}" if proto == "udp" else str(port_num)
                if auth:
                    port_field += "*"

                svc_field = f" {svc}" if svc else ""

                no_version_key = f"no_version:{port_num}/{svc}"
                no_scripts_key = f"no_scripts:{port_num}/{svc}"

                if no_version_key in gaps:
                    prod_field = " ?"
                else:
                    product = p.get("product", "")
                    version = p.get("version", "")
                    if product or version:
                        prod_name = product.replace(" ", "-") if product else ""
                        if prod_name and version:
                            prod_field = f" {prod_name}/{version}"
                        elif prod_name:
                            prod_field = f" {prod_name}"
                        else:
                            prod_field = f" /{version}"
                    else:
                        prod_field = ""

                scripts_flag = "!" if no_scripts_key in gaps else ""
                lines.append(f" {port_field}{svc_field}{prod_field}{scripts_flag}")

            blocks.append("\n".join(lines))

        return "\n\n".join(blocks)
