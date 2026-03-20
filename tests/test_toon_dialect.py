import pytest
from src.utils.toon_dialect import ToonDialect


def _host(target="10.0.0.1", type_="Database Server", crit="CRITICAL",
          os_name="Linux 4.15", ports=None):
    """Build a minimal post-classification TOON host dict."""
    return {
        "target": target,
        "type": type_,
        "criticality": crit,
        "os": {"name": os_name, "accuracy": 85},
        "ports": ports or [],
    }


def _port(port=80, service="http", product="", version="",
          auth=False, protocol="tcp", exploits=None):
    return {
        "port": port, "protocol": protocol, "service": service,
        "product": product, "version": version,
        "auth_required": auth, "scripts": [],
        "exploits": exploits or [],
    }


# ── serialize_report ────────────────────────────────────────────────────────

class TestSerializeReport:

    def test_critical_host_full_block(self):
        host = _host(ports=[_port(5432, "postgresql", "PostgreSQL DB", "9.6.0")])
        result = ToonDialect.serialize_report([host])
        assert result.startswith("10.0.0.1 D C Linux-4.15")
        assert " 5432 postgresql PostgreSQL-DB/9.6.0" in result

    def test_low_host_single_line(self):
        host = _host(crit="LOW", type_="Generic Host",
                     ports=[_port(80, "http")])
        result = ToonDialect.serialize_report([host])
        assert result.strip() == "10.0.0.1 G L"
        assert "80" not in result

    def test_medium_host_single_line(self):
        host = _host(crit="MEDIUM", type_="Web Server",
                     ports=[_port(80, "http")])
        result = ToonDialect.serialize_report([host])
        assert result.strip() == "10.0.0.1 W M"

    def test_unknown_os_omitted(self):
        host = _host(os_name="unknown",
                     ports=[_port(22, "ssh")])
        result = ToonDialect.serialize_report([host])
        first_line = result.splitlines()[0]
        assert first_line == "10.0.0.1 D C"

    def test_os_spaces_replaced_with_hyphens(self):
        host = _host(os_name="Windows Server 2019")
        result = ToonDialect.serialize_report([host])
        assert "Windows-Server-2019" in result.splitlines()[0]

    def test_auth_required_port_gets_star(self):
        host = _host(ports=[_port(22, "ssh", auth=True)])
        result = ToonDialect.serialize_report([host])
        assert " 22*" in result

    def test_no_auth_port_no_star(self):
        host = _host(ports=[_port(80, "http", auth=False)])
        result = ToonDialect.serialize_report([host])
        assert " 80 " in result
        assert "80*" not in result

    def test_udp_port_gets_u_prefix(self):
        host = _host(ports=[_port(53, "domain", protocol="udp")])
        result = ToonDialect.serialize_report([host])
        assert " u:53 " in result

    def test_tcp_protocol_omitted(self):
        host = _host(ports=[_port(80, "http", protocol="tcp")])
        result = ToonDialect.serialize_report([host])
        assert "tcp" not in result

    def test_empty_product_version_omitted(self):
        host = _host(ports=[_port(80, "http", product="", version="")])
        result = ToonDialect.serialize_report([host])
        port_line = [l for l in result.splitlines() if "80" in l][0]
        assert port_line.strip() == "80 http"

    def test_cve_prefix_stripped(self):
        exploit = {"cve": "CVE-1999-0862", "cvss": 2.1, "source": "nvd"}
        host = _host(ports=[_port(5432, "postgresql", exploits=[exploit])])
        result = ToonDialect.serialize_report([host])
        assert "CVE-" not in result
        assert "1999-0862:2.1:n" in result

    def test_cve_source_codes(self):
        exploits = [
            {"cve": "CVE-0001-0001", "cvss": 9.0, "source": "nvd"},
            {"cve": "CVE-0001-0002", "cvss": 7.5, "source": "vulners"},
            {"cve": "CVE-0001-0003", "cvss": 5.0, "source": "circl"},
        ]
        host = _host(ports=[_port(5432, "postgresql", exploits=exploits)])
        result = ToonDialect.serialize_report([host])
        assert ":n" in result
        assert ":v" in result
        assert ":c" in result

    def test_exploits_capped_at_5(self):
        exploits = [
            {"cve": f"CVE-2000-000{i}", "cvss": float(i), "source": "nvd"}
            for i in range(8)
        ]
        host = _host(ports=[_port(5432, "postgresql", exploits=exploits)])
        result = ToonDialect.serialize_report([host])
        # Top 5 by CVSS are scores 7,6,5,4,3 → CVE ids 0007,0006,0005,0004,0003
        assert result.count("2000-000") == 5
        # The 3 lowest-CVSS entries must be absent
        assert "2000-0000" not in result
        assert "2000-0001" not in result
        assert "2000-0002" not in result

    def test_exploits_sorted_by_cvss_descending(self):
        exploits = [
            {"cve": "CVE-2000-0001", "cvss": 2.0, "source": "nvd"},
            {"cve": "CVE-2000-0002", "cvss": 9.0, "source": "nvd"},
        ]
        host = _host(ports=[_port(5432, "postgresql", exploits=exploits)])
        result = ToonDialect.serialize_report([host])
        idx_high = result.index("2000-0002")
        idx_low = result.index("2000-0001")
        assert idx_high < idx_low  # higher CVSS first

    def test_no_exploits_no_brackets(self):
        host = _host(ports=[_port(80, "http")])
        result = ToonDialect.serialize_report([host])
        assert "[" not in result

    def test_multiple_hosts_blank_line_separator(self):
        h1 = _host("10.0.0.1", ports=[_port(80)])
        h2 = _host("10.0.0.2", crit="LOW", type_="Generic Host")
        result = ToonDialect.serialize_report([h1, h2])
        assert "\n\n" in result

    def test_port_indent_one_space(self):
        host = _host(ports=[_port(80, "http")])
        result = ToonDialect.serialize_report([host])
        port_line = [l for l in result.splitlines() if "80" in l][0]
        assert port_line.startswith(" ")
        assert not port_line.startswith("  ")

    def test_all_type_aliases(self):
        types = [
            ("Database Server", "D"), ("Mail Server", "M"), ("Router", "R"),
            ("Firewall", "F"), ("Active Directory / LDAP", "A"),
            ("Jump Host", "J"), ("Web Server", "W"), ("Application Server", "S"),
            ("IoT Camera", "I"), ("NAS Appliance", "N"),
            ("Windows File Server", "X"), ("DNS Server", "Z"),
            ("Generic Host", "G"),
        ]
        for full_name, alias in types:
            host = _host(type_=full_name, crit="LOW")
            result = ToonDialect.serialize_report([host])
            first_token = result.split()[1]
            assert first_token == alias, f"{full_name} should map to {alias}, got {first_token}"

    def test_unknown_type_falls_back_to_g(self):
        host = _host(type_="Mystery Device", crit="LOW")
        result = ToonDialect.serialize_report([host])
        assert result.split()[1] == "G"


# ── serialize_classify ──────────────────────────────────────────────────────

def _bundle(ip="10.0.0.1", top_type="Database Server", top_score=8,
            runner_type="Web Server", runner_score=2,
            os_dict=None, ports=None):
    """Build a minimal evidence bundle as produced by build_evidence_bundle()."""
    return {
        "ip": ip,
        "ports": ports or [{"port": 5432, "service": "postgresql",
                             "product": "PostgreSQL DB", "version": "9.6.0"}],
        "os": os_dict,  # None means unknown
        "hostname": None,
        "static": {
            "top_type": top_type,
            "top_score": top_score,
            "signals": [f"Ports [5432] matched (+2)"],
            "runner_up": {"type": runner_type, "score": runner_score},
        },
        "scripts": {},
    }


class TestSerializeClassify:

    def test_host_line_with_os(self):
        b = _bundle(os_dict={"name": "Linux 4.15", "accuracy": 85})
        result = ToonDialect.serialize_classify([b])
        assert result.startswith("10.0.0.1 D C Linux-4.15")

    def test_host_line_no_os(self):
        b = _bundle(os_dict=None)
        result = ToonDialect.serialize_classify([b])
        first_line = result.splitlines()[0]
        assert first_line == "10.0.0.1 D C"

    def test_m_line_present(self):
        b = _bundle(top_score=8, runner_score=2)
        result = ToonDialect.serialize_classify([b])
        assert " M: D:8>W:2" in result

    def test_m_line_uses_type_aliases(self):
        b = _bundle(top_type="Mail Server", top_score=5,
                    runner_type="Generic Host", runner_score=0)
        result = ToonDialect.serialize_classify([b])
        assert " M: M:5>G:0" in result

    def test_criticality_critical_from_score(self):
        # top_score >= CRITICAL_THRESHOLD (4) → C
        b = _bundle(top_score=6)
        result = ToonDialect.serialize_classify([b])
        assert result.split()[2] == "C"

    def test_criticality_high_from_score(self):
        # top_score >= HIGH_THRESHOLD (2) but < CRITICAL_THRESHOLD → H
        b = _bundle(top_score=3)
        result = ToonDialect.serialize_classify([b])
        assert result.split()[2] == "H"

    def test_criticality_medium_from_score(self):
        b = _bundle(top_score=1)
        result = ToonDialect.serialize_classify([b])
        assert result.split()[2] == "M"

    def test_criticality_low_from_zero_score(self):
        b = _bundle(top_score=0)
        result = ToonDialect.serialize_classify([b])
        assert result.split()[2] == "L"

    def test_port_line_no_auth_no_star(self):
        # Evidence bundles have no auth_required field
        b = _bundle(ports=[{"port": 5432, "service": "postgresql",
                             "product": "", "version": ""}])
        result = ToonDialect.serialize_classify([b])
        assert "5432*" not in result
        assert " 5432 " in result

    def test_port_line_no_exploits(self):
        b = _bundle()
        result = ToonDialect.serialize_classify([b])
        assert "[" not in result

    def test_port_product_version_formatted(self):
        b = _bundle(ports=[{"port": 5432, "service": "postgresql",
                             "product": "PostgreSQL DB", "version": "9.6.0"}])
        result = ToonDialect.serialize_classify([b])
        assert "PostgreSQL-DB/9.6.0" in result

    def test_multiple_hosts_blank_line_separator(self):
        b1 = _bundle("10.0.0.1")
        b2 = _bundle("10.0.0.2", top_type="Web Server")
        result = ToonDialect.serialize_classify([b1, b2])
        assert "\n\n" in result

    def test_scripts_dropped(self):
        b = _bundle()
        b["scripts"] = {"http-title": "Apache Default Page"}
        result = ToonDialect.serialize_classify([b])
        assert "http-title" not in result
        assert "Apache" not in result

    def test_port_indent_one_space(self):
        b = _bundle(ports=[{"port": 5432, "service": "postgresql",
                             "product": "", "version": ""}])
        result = ToonDialect.serialize_classify([b])
        port_line = [l for l in result.splitlines() if "5432" in l and "M:" not in l][0]
        assert port_line.startswith(" ")
        assert not port_line.startswith("  ")


# ── compress_history ────────────────────────────────────────────────────────

def _history_entry(depth, hosts):
    """Build a scan_history entry."""
    return {"depth": depth, "hosts": hosts}


def _hhost(ip="10.0.0.1", type_="Database Server",
           crit="CRITICAL", ports=None):
    return {"ip": ip, "type": type_, "criticality": crit,
            "ports": ports or [5432, 22]}


class TestCompressHistory:

    def test_empty_list_returns_header_only(self):
        result = ToonDialect.compress_history([])
        assert "History" in result
        assert "aliases" in result

    def test_single_depth_format(self):
        history = [_history_entry(1, [_hhost()])]
        result = ToonDialect.compress_history(history)
        assert "d1: 10.0.0.1/D/C/5432,22" in result

    def test_two_depths(self):
        history = [
            _history_entry(1, [_hhost()]),
            _history_entry(2, [_hhost(ports=[5432, 22, 3306])]),
        ]
        result = ToonDialect.compress_history(history)
        assert "d1:" in result
        assert "d2:" in result

    def test_caps_to_last_two_depths(self):
        history = [
            _history_entry(1, [_hhost()]),
            _history_entry(2, [_hhost()]),
            _history_entry(3, [_hhost(ports=[443])]),
        ]
        result = ToonDialect.compress_history(history)
        assert "d1:" not in result
        assert "d2:" in result
        assert "d3:" in result

    def test_depth_n_uses_entry_depth_not_index(self):
        # Even after slicing, the depth integer in the output = entry["depth"]
        history = [
            _history_entry(2, [_hhost()]),
            _history_entry(3, [_hhost()]),
        ]
        result = ToonDialect.compress_history(history)
        assert "d2:" in result
        assert "d3:" in result
        assert "d1:" not in result

    def test_multiple_hosts_pipe_separated(self):
        history = [_history_entry(1, [
            _hhost("10.0.0.1"),
            _hhost("10.0.0.2", type_="Web Server", crit="HIGH"),
        ])]
        result = ToonDialect.compress_history(history)
        assert "10.0.0.1/D/C" in result
        assert "10.0.0.2/W/H" in result
        assert " | " in result

    def test_ports_bare_csv_integers(self):
        history = [_history_entry(1, [_hhost(ports=[80, 443, 8080])])]
        result = ToonDialect.compress_history(history)
        assert "80,443,8080" in result

    def test_type_aliases_applied(self):
        history = [_history_entry(1, [
            _hhost(type_="Mail Server", crit="CRITICAL"),
        ])]
        result = ToonDialect.compress_history(history)
        assert "/M/C/" in result

    def test_criticality_aliases_applied(self):
        history = [_history_entry(1, [
            _hhost(crit="HIGH"),
        ])]
        result = ToonDialect.compress_history(history)
        assert "/D/H/" in result

    def test_decoder_header_present(self):
        history = [_history_entry(1, [_hhost()])]
        result = ToonDialect.compress_history(history)
        # Header should contain alias legend
        assert "D=Database" in result
        assert "C=CRITICAL" in result

    def test_depth_lines_newline_separated(self):
        history = [
            _history_entry(1, [_hhost()]),
            _history_entry(2, [_hhost()]),
        ]
        result = ToonDialect.compress_history(history)
        lines = result.splitlines()
        d_lines = [l for l in lines if l.startswith("d")]
        assert len(d_lines) == 2


# ── render_with_gaps ────────────────────────────────────────────────────────

def _gapped_host(ip="10.0.0.1", type_="Database Server", crit="CRITICAL",
                 os_name="Linux", os_acc=85, ports=None):
    return {
        "target": ip, "type": type_, "criticality": crit,
        "os": {"name": os_name, "accuracy": os_acc},
        "ports": ports or [],
    }


def _gport(port=80, service="http", product="", version="",
           auth=False, protocol="tcp", scripts=None):
    return {
        "port": port, "protocol": protocol, "service": service,
        "product": product, "version": version,
        "auth_required": auth, "scripts": scripts or [], "exploits": [],
    }


class TestRenderWithGaps:

    def test_os_unknown_shows_question_mark(self):
        host = _gapped_host(os_name="unknown", os_acc=0)
        gap_map = {"10.0.0.1": ["os_unknown"]}
        result = ToonDialect.render_with_gaps([host], gap_map)
        assert result.splitlines()[0].endswith("?")

    def test_known_os_shown_normally(self):
        host = _gapped_host(os_name="Linux-4.15", os_acc=90)
        gap_map = {}
        result = ToonDialect.render_with_gaps([host], gap_map)
        assert "Linux-4.15" in result.splitlines()[0]

    def test_no_version_port_shows_question_mark(self):
        host = _gapped_host(ports=[_gport(22, "ssh")])
        gap_map = {"10.0.0.1": ["no_version:22/ssh"]}
        result = ToonDialect.render_with_gaps([host], gap_map)
        port_line = [l for l in result.splitlines() if "22" in l][0]
        assert "?" in port_line

    def test_known_version_port_shown_normally(self):
        host = _gapped_host(ports=[_gport(22, "ssh", product="OpenSSH", version="8.0")])
        gap_map = {}
        result = ToonDialect.render_with_gaps([host], gap_map)
        assert "OpenSSH/8.0" in result

    def test_no_scripts_port_shows_exclamation(self):
        host = _gapped_host(ports=[_gport(3306, "mysql", product="MySQL", version="8.0")])
        gap_map = {"10.0.0.1": ["no_scripts:3306/mysql"]}
        result = ToonDialect.render_with_gaps([host], gap_map)
        port_line = [l for l in result.splitlines() if "3306" in l][0]
        assert port_line.endswith("!")

    def test_port_with_no_gaps_has_no_markers(self):
        host = _gapped_host(ports=[_gport(80, "http", product="Apache", version="2.4")])
        gap_map = {}
        result = ToonDialect.render_with_gaps([host], gap_map)
        port_line = [l for l in result.splitlines() if "80" in l][0]
        assert "?" not in port_line
        assert "!" not in port_line

    def test_all_hosts_rendered_not_just_critical(self):
        hosts = [
            _gapped_host("10.0.0.1", crit="CRITICAL"),
            _gapped_host("10.0.0.2", crit="LOW", type_="Generic Host"),
        ]
        result = ToonDialect.render_with_gaps(hosts, {})
        assert "10.0.0.1" in result
        assert "10.0.0.2" in result

    def test_empty_hosts_returns_empty_string(self):
        assert ToonDialect.render_with_gaps([], {}) == ""

    def test_multiple_hosts_blank_line_separator(self):
        hosts = [_gapped_host("10.0.0.1"), _gapped_host("10.0.0.2")]
        result = ToonDialect.render_with_gaps(hosts, {})
        assert "\n\n" in result
