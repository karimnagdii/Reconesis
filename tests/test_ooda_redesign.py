import pytest
from unittest.mock import MagicMock, patch
from src.core.reconesis import ReconesisEngine
from src.core.agent import GroqAgent


def _make_port(port=80, service="http", version=None, product=None, scripts=None, exploits=None):
    return {
        "port": port,
        "service": service,
        "version": version or "",
        "product": product or "",
        "scripts": scripts or [],
        "exploits": exploits or [],
    }


def _make_host(ip="192.168.1.1", ports=None, os_accuracy=0):
    return {
        "target": ip,
        "status": "up",
        "os": {"name": "unknown", "accuracy": os_accuracy},
        "ports": ports or [],
        "criticality": "LOW",
        "type": "Generic Host",
        "metrics": [],
    }


class TestIsRicher:
    def test_richer_when_new_has_version_and_old_does_not(self):
        new = _make_port(version="7.4")
        old = _make_port(version="")
        assert ReconesisEngine._is_richer(new, old) is True

    def test_not_richer_when_both_have_version(self):
        new = _make_port(version="7.4")
        old = _make_port(version="8.0")
        assert ReconesisEngine._is_richer(new, old) is False

    def test_richer_when_new_has_product_and_old_does_not(self):
        new = _make_port(product="OpenSSH")
        old = _make_port(product="")
        assert ReconesisEngine._is_richer(new, old) is True

    def test_richer_when_new_has_scripts_and_old_does_not(self):
        new = _make_port(scripts=[{"id": "ssh-hostkey", "output": "..."}])
        old = _make_port(scripts=[])
        assert ReconesisEngine._is_richer(new, old) is True

    def test_richer_when_new_has_exploits_and_old_does_not(self):
        new = _make_port(exploits=[{"cve": "CVE-2021-1234", "cvss": 9.8}])
        old = _make_port(exploits=[])
        assert ReconesisEngine._is_richer(new, old) is True

    def test_not_richer_when_new_adds_nothing(self):
        new = _make_port()
        old = _make_port()
        assert ReconesisEngine._is_richer(new, old) is False


class TestMergeHost:
    def _make_engine(self):
        with patch("src.core.reconesis.NmapExecutor"), \
             patch("src.core.reconesis.GroqAgent"), \
             patch("src.core.reconesis.TOONParser"), \
             patch("src.core.reconesis.CriticalityAssessor"), \
             patch("src.core.reconesis.ExploitLookup"):
            return ReconesisEngine()

    def test_new_host_inserted_returns_true(self):
        engine = self._make_engine()
        host = _make_host("10.0.0.1")
        assert engine._merge_host(host) is True
        assert "10.0.0.1" in engine._host_map

    def test_duplicate_host_no_richer_data_returns_false(self):
        engine = self._make_engine()
        host = _make_host("10.0.0.1", ports=[_make_port(80)])
        engine._merge_host(host)
        assert engine._merge_host(host) is False

    def test_existing_host_gets_new_port(self):
        engine = self._make_engine()
        engine._merge_host(_make_host("10.0.0.1", ports=[_make_port(80)]))
        engine._merge_host(_make_host("10.0.0.1", ports=[_make_port(443)]))
        ports = {p["port"] for p in engine._host_map["10.0.0.1"]["ports"]}
        assert ports == {80, 443}

    def test_richer_port_overwrites_existing(self):
        engine = self._make_engine()
        engine._merge_host(_make_host("10.0.0.1", ports=[_make_port(22, version="")]))
        engine._merge_host(_make_host("10.0.0.1", ports=[_make_port(22, version="OpenSSH 8.0")]))
        port = engine._host_map["10.0.0.1"]["ports"][0]
        assert port["version"] == "OpenSSH 8.0"

    def test_less_rich_port_does_not_overwrite(self):
        engine = self._make_engine()
        engine._merge_host(_make_host("10.0.0.1", ports=[_make_port(22, version="OpenSSH 8.0")]))
        engine._merge_host(_make_host("10.0.0.1", ports=[_make_port(22, version="")]))
        port = engine._host_map["10.0.0.1"]["ports"][0]
        assert port["version"] == "OpenSSH 8.0"

    def test_better_os_overwrites(self):
        engine = self._make_engine()
        engine._merge_host(_make_host("10.0.0.1", os_accuracy=0))
        engine._merge_host(_make_host("10.0.0.1", os_accuracy=90))
        assert engine._host_map["10.0.0.1"]["os"]["accuracy"] == 90

    def test_worse_os_does_not_overwrite(self):
        engine = self._make_engine()
        engine._merge_host(_make_host("10.0.0.1", os_accuracy=90))
        engine._merge_host(_make_host("10.0.0.1", os_accuracy=10))
        assert engine._host_map["10.0.0.1"]["os"]["accuracy"] == 90

    def test_host_missing_os_key_does_not_crash(self):
        engine = self._make_engine()
        host = {"target": "10.0.0.2", "status": "up", "ports": []}  # no "os" key
        engine._merge_host(host)
        assert "10.0.0.2" in engine._host_map

    def test_all_hosts_property_returns_list(self):
        engine = self._make_engine()
        engine._merge_host(_make_host("10.0.0.1"))
        engine._merge_host(_make_host("10.0.0.2"))
        assert len(engine._all_hosts) == 2

    def test_all_hosts_setter_rebuilds_host_map(self):
        engine = self._make_engine()
        hosts = [_make_host("10.0.0.1"), _make_host("10.0.0.2")]
        engine._all_hosts = hosts
        assert set(engine._host_map.keys()) == {"10.0.0.1", "10.0.0.2"}

    def test_all_hosts_setter_drops_hosts_without_target(self):
        engine = self._make_engine()
        hosts = [_make_host("10.0.0.1"), {"status": "up", "ports": []}]  # second has no target
        engine._all_hosts = hosts
        assert list(engine._host_map.keys()) == ["10.0.0.1"]

    def test_host_map_initialized_empty_before_start_scan(self):
        engine = self._make_engine()
        assert engine._all_hosts == []


class TestComputeGaps:
    def _make_engine(self):
        with patch("src.core.reconesis.NmapExecutor"), \
             patch("src.core.reconesis.GroqAgent"), \
             patch("src.core.reconesis.TOONParser"), \
             patch("src.core.reconesis.CriticalityAssessor"), \
             patch("src.core.reconesis.ExploitLookup"):
            return ReconesisEngine()

    def test_no_gaps_when_host_fully_known(self):
        engine = self._make_engine()
        host = _make_host("10.0.0.1", os_accuracy=90, ports=[
            _make_port(80, version="Apache 2.4", scripts=[{"id": "http-title", "output": "..."}])
        ])
        engine._merge_host(host)
        assert engine._compute_gaps() == []

    def test_os_unknown_gap_reported(self):
        engine = self._make_engine()
        engine._merge_host(_make_host("10.0.0.1", os_accuracy=0))
        gaps = engine._compute_gaps()
        assert len(gaps) == 1
        assert "os_unknown" in gaps[0]["gaps"]

    def test_no_version_gap_reported(self):
        engine = self._make_engine()
        engine._merge_host(_make_host("10.0.0.1", os_accuracy=90, ports=[_make_port(22, version="")]))
        gaps = engine._compute_gaps()
        assert any("no_version:22" in g for g in gaps[0]["gaps"])

    def test_interesting_port_without_scripts_reported(self):
        engine = self._make_engine()
        # Port 3306 (MySQL) is in INTERESTING_PORTS
        engine._merge_host(_make_host("10.0.0.1", os_accuracy=90, ports=[
            _make_port(3306, version="MySQL 8.0", scripts=[])
        ]))
        gaps = engine._compute_gaps()
        assert any("no_scripts:3306" in g for g in gaps[0]["gaps"])

    def test_non_interesting_port_without_scripts_not_reported(self):
        engine = self._make_engine()
        # Port 9999 is NOT in INTERESTING_PORTS
        engine._merge_host(_make_host("10.0.0.1", os_accuracy=90, ports=[
            _make_port(9999, version="custom", scripts=[])
        ]))
        assert engine._compute_gaps() == []

    def test_host_without_os_key_does_not_crash(self):
        engine = self._make_engine()
        host = {"target": "10.0.0.1", "status": "up", "ports": []}
        engine._merge_host(host)
        # Should not raise, should report os_unknown
        gaps = engine._compute_gaps()
        assert any("os_unknown" in g["gaps"] for g in gaps)

    def test_empty_host_map_returns_empty(self):
        engine = self._make_engine()
        assert engine._compute_gaps() == []


class TestHelperMethods:
    def _make_engine(self):
        with patch("src.core.reconesis.NmapExecutor"), \
             patch("src.core.reconesis.GroqAgent"), \
             patch("src.core.reconesis.TOONParser"), \
             patch("src.core.reconesis.CriticalityAssessor"), \
             patch("src.core.reconesis.ExploitLookup"):
            return ReconesisEngine()

    def test_update_scan_history_appends_entry(self):
        engine = self._make_engine()
        classified = [_make_host("10.0.0.1", ports=[_make_port(22)])]
        engine._update_scan_history(depth=1, classified=classified)
        assert len(engine.scan_history) == 1
        entry = engine.scan_history[0]
        assert entry["depth"] == 1
        assert entry["hosts"][0]["ip"] == "10.0.0.1"
        assert 22 in entry["hosts"][0]["ports"]

    def test_update_scan_history_accumulates_across_depths(self):
        engine = self._make_engine()
        engine._update_scan_history(1, [_make_host("10.0.0.1")])
        engine._update_scan_history(2, [_make_host("10.0.0.1"), _make_host("10.0.0.2")])
        assert len(engine.scan_history) == 2
        assert len(engine.scan_history[1]["hosts"]) == 2

    def test_execute_and_merge_empty_command_does_not_call_executor(self):
        engine = self._make_engine()
        engine._execute_and_merge("")
        engine.executor.execute.assert_not_called()

    def test_execute_and_merge_merges_parsed_hosts(self):
        engine = self._make_engine()
        engine.executor.execute.return_value = ("<xml>", 10)
        engine.parser.parse.return_value = [_make_host("10.0.0.5")]
        engine._execute_and_merge("nmap -sS 10.0.0.0/24")
        assert "10.0.0.5" in engine._host_map
        assert engine.metrics["total_packets"] == 10

    def test_execute_and_merge_no_xml_output_does_not_crash(self):
        engine = self._make_engine()
        engine.executor.execute.return_value = ("", 0)
        engine._execute_and_merge("nmap -sS 10.0.0.0/24")
        assert engine._host_map == {}


class TestGroqAgentDecide:
    def _make_agent(self, groq_response: str):
        with patch("src.core.agent.Config") as mock_cfg:
            mock_cfg.GROQ_API_KEY = "test-key"
            mock_cfg.GROQ_MODEL = "test-model"
            mock_cfg.GROQ_API_URL = "http://test"
            agent = GroqAgent()
        agent._query_groq = MagicMock(return_value=(groq_response, "stop"))
        return agent

    def test_valid_json_response_returned(self):
        agent = self._make_agent('{"command": "nmap -sV 10.0.0.1", "rationale": "fill gaps", "continue": true, "new_targets": []}')
        result = agent.decide(hosts=[], gap_report=[], scan_history=[])
        assert result["command"] == "nmap -sV 10.0.0.1"
        assert result["continue"] is True
        assert result["new_targets"] == []

    def test_missing_command_key_returns_empty(self):
        agent = self._make_agent('{"rationale": "done", "continue": false}')
        result = agent.decide(hosts=[], gap_report=[], scan_history=[])
        assert result == {}

    def test_malformed_json_returns_empty(self):
        agent = self._make_agent("this is not json at all")
        result = agent.decide(hosts=[], gap_report=[], scan_history=[])
        assert result == {}

    def test_code_fenced_json_is_stripped_and_parsed(self):
        fenced = '```json\n{"command": "nmap -O 10.0.0.1", "rationale": "os", "continue": true, "new_targets": []}\n```'
        agent = self._make_agent(fenced)
        result = agent.decide(hosts=[], gap_report=[], scan_history=[])
        assert result["command"] == "nmap -O 10.0.0.1"

    def test_defaults_applied_when_keys_missing(self):
        agent = self._make_agent('{"command": "nmap -sS 10.0.0.1"}')
        result = agent.decide(hosts=[], gap_report=[], scan_history=[])
        assert result["continue"] is True
        assert result["new_targets"] == []

    def test_continue_false_preserved(self):
        agent = self._make_agent('{"command": "nmap -sS 10.0.0.1", "continue": false, "new_targets": []}')
        result = agent.decide(hosts=[], gap_report=[], scan_history=[])
        assert result["continue"] is False
