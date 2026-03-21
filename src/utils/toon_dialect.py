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
    def _render_port(
        p: dict,
        *,
        include_auth: bool = True,
        include_protocol: bool = True,
        include_gaps: bool = False,
        include_exploits: bool = False,
        gap_keys: set = None,
    ) -> str:
        """Unified port-to-string renderer.

        Flags:
          include_auth:     append * after the port number when auth_required is True
          include_protocol: prefix port with u: when protocol is "udp"
                            (independent of include_auth — each flag controls only its own marker)
          include_gaps:     render ? for unknown version, ! for missing scripts
                            (requires gap_keys set from render_with_gaps caller)
          include_exploits: append [cve:cvss:src ...] exploit field
                            INVARIANT: include_exploits=True requires include_protocol=True
        """
        assert not (include_exploits and not include_protocol), (
            "_render_port: include_exploits=True requires include_protocol=True"
        )
        if gap_keys is None:
            gap_keys = set()

        port_num = p["port"]
        service = p.get("service", "")
        svc_field = f" {service}" if service else ""

        # Port field: protocol prefix and auth marker
        if include_protocol:
            proto = p.get("protocol", "tcp")
            port_field = f"u:{port_num}" if proto == "udp" else str(port_num)
        else:
            port_field = str(port_num)

        if include_auth and p.get("auth_required", False):
            port_field += "*"

        # Product / version field — or gap marker
        no_version_key = f"no_version:{port_num}/{service}"
        if include_gaps and no_version_key in gap_keys:
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

        # Scripts gap marker
        no_scripts_key = f"no_scripts:{port_num}/{service}"
        scripts_flag = ""
        if include_gaps and no_scripts_key in gap_keys:
            scripts_flag = "!"

        # Exploit field
        exploit_field = ""
        if include_exploits:
            exploits = sorted(
                p.get("exploits", []),
                key=lambda e: e.get("cvss", 0),
                reverse=True
            )[:5]
            if exploits:
                parts = []
                for e in exploits:
                    cve_id = e.get("cve", "").replace("CVE-", "")
                    cvss = e.get("cvss", 0)
                    src = _SOURCE_CODE.get(e.get("source", ""), e.get("source", ""))
                    parts.append(f"{cve_id}:{cvss}:{src}")
                exploit_field = " [" + " ".join(parts) + "]"

        return f"{port_field}{svc_field}{prod_field}{scripts_flag}{exploit_field}"

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
        return ToonDialect._render_port(
            p,
            include_auth=True,
            include_protocol=True,
            include_exploits=True,
        )

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
                port_str = ToonDialect._render_port(
                    p,
                    include_auth=False,
                    include_protocol=False,
                )
                port_lines.append(f" {port_str}")

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
                port_str = ToonDialect._render_port(
                    p,
                    include_auth=True,
                    include_protocol=True,
                    include_gaps=True,
                    include_exploits=False,
                    gap_keys=set(gaps),
                )
                lines.append(f" {port_str}")

            blocks.append("\n".join(lines))

        return "\n\n".join(blocks)
