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

    def test_missing_command_key_raises_parse_error(self):
        from src.utils.exceptions import ReconesisParseError
        agent = self._make_agent('{"rationale": "done", "continue": false}')
        with pytest.raises((ReconesisParseError, ValueError)):
            agent.decide(hosts=[], gap_report=[], scan_history=[])

    def test_malformed_json_raises_parse_error(self):
        from src.utils.exceptions import ReconesisParseError
        agent = self._make_agent("this is not json at all")
        with pytest.raises(ReconesisParseError):
            agent.decide(hosts=[], gap_report=[], scan_history=[])

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


class TestRunHunter:
    def _make_engine(self):
        with patch("src.core.reconesis.NmapExecutor"), \
             patch("src.core.reconesis.GroqAgent"), \
             patch("src.core.reconesis.TOONParser"), \
             patch("src.core.reconesis.CriticalityAssessor"), \
             patch("src.core.reconesis.ExploitLookup"):
            engine = ReconesisEngine()
        return engine

    def test_returns_false_when_no_hunter_command(self):
        engine = self._make_engine()
        engine.agent.generate_strategy.return_value = ""
        result = engine._run_hunter([{"ip": "10.0.0.1", "type": "Web Server"}])
        assert result is False

    def test_returns_true_on_successful_scan(self):
        engine = self._make_engine()
        engine.agent.generate_strategy.return_value = "nmap -sV 10.0.0.1"
        engine.executor.execute.return_value = ("<xml>", 5)
        engine.parser.parse.return_value = [_make_host("10.0.0.1", ports=[_make_port(443, version="nginx")])]
        engine._merge_host(_make_host("10.0.0.1", ports=[_make_port(80)]))
        result = engine._run_hunter([{"ip": "10.0.0.1", "type": "Web Server"}])
        assert result is True

    def test_hunter_enriches_existing_host_via_merge(self):
        engine = self._make_engine()
        engine.agent.generate_strategy.return_value = "nmap -sV 10.0.0.1"
        engine.executor.execute.return_value = ("<xml>", 5)
        engine.parser.parse.return_value = [_make_host("10.0.0.1", ports=[_make_port(22, version="OpenSSH 8.0")])]
        engine._merge_host(_make_host("10.0.0.1", ports=[_make_port(22, version="")]))
        engine._run_hunter([{"ip": "10.0.0.1", "type": "Generic Host"}])
        port = engine._host_map["10.0.0.1"]["ports"][0]
        assert port["version"] == "OpenSSH 8.0"

    def test_hunter_enriched_event_emitted_only_on_change(self):
        engine = self._make_engine()
        engine._emit = MagicMock()
        engine.agent.generate_strategy.return_value = "nmap -sV 10.0.0.1"
        engine.executor.execute.return_value = ("<xml>", 5)
        # Hunter returns same data as what's already in host_map (no change)
        host = _make_host("10.0.0.1", ports=[_make_port(80, version="Apache")])
        engine._merge_host(host)
        engine.parser.parse.return_value = [_make_host("10.0.0.1", ports=[_make_port(80, version="Apache")])]
        engine._run_hunter([{"ip": "10.0.0.1", "type": "Web Server"}])
        enriched_calls = [c for c in engine._emit.call_args_list if c[0][0] == "host_enriched"]
        assert len(enriched_calls) == 0


class TestStartScan:
    def _make_engine(self, discovery_hosts=None, port_scan_hosts=None, hunter_hosts=None, decide_response=None):
        """Build an engine with controllable stubs for a full scan flow."""
        with patch("src.core.reconesis.NmapExecutor"), \
             patch("src.core.reconesis.GroqAgent"), \
             patch("src.core.reconesis.TOONParser"), \
             patch("src.core.reconesis.CriticalityAssessor"), \
             patch("src.core.reconesis.ExploitLookup"):
            engine = ReconesisEngine()

        # Discovery returns live IPs
        discovery_hosts = discovery_hosts or [_make_host("10.0.0.1")]
        engine._run_discovery = MagicMock(return_value=[h["target"] for h in discovery_hosts])

        # Port scan returns hosts
        port_scan_hosts = port_scan_hosts or [_make_host("10.0.0.1", ports=[_make_port(80)])]
        engine._run_port_scan = MagicMock(return_value=port_scan_hosts)

        # Classify: return hosts as-is with criticality LOW, no critical targets
        def fake_classify(hosts):
            for h in hosts:
                h.setdefault("criticality", "LOW")
                h.setdefault("type", "Generic Host")
                h.setdefault("metrics", [])
            return hosts, []
        engine._classify_hosts = MagicMock(side_effect=fake_classify)

        # Hunter not called by default (no critical targets)
        engine._run_hunter = MagicMock(return_value=True)

        # decide() returns stop-after-first-depth
        decide_response = decide_response or {"command": "nmap -sV 10.0.0.1", "continue": False, "new_targets": []}
        engine.agent.decide = MagicMock(return_value=decide_response)

        # execute_and_merge: stub out
        engine._execute_and_merge = MagicMock()

        # CVE enrichment and report: stub out
        engine._run_cve_enrichment = MagicMock()
        engine._generate_report = MagicMock()

        # Hash: always unique to avoid early saturation
        engine.parser.compute_hash = MagicMock(side_effect=lambda x: str(len(x)) + str(id(x)))

        return engine

    def test_discovery_failure_returns_early(self):
        engine = self._make_engine()
        engine._run_discovery = MagicMock(return_value=[])
        engine.start_scan("10.0.0.0/24")
        engine._generate_report.assert_not_called()

    def test_port_scan_failure_at_depth_1_generates_partial_report(self):
        engine = self._make_engine()
        engine._run_port_scan = MagicMock(return_value=[])
        engine.start_scan("10.0.0.0/24")
        engine._generate_report.assert_called_once_with(partial=True)

    def test_hosts_merged_into_host_map_after_observe(self):
        engine = self._make_engine()
        engine.start_scan("10.0.0.0/24")
        assert "10.0.0.1" in engine._host_map

    def test_cve_enrichment_and_report_called_at_end(self):
        engine = self._make_engine()
        engine.start_scan("10.0.0.0/24")
        engine._run_cve_enrichment.assert_called_once()
        engine._generate_report.assert_called_once_with()

    def test_loop_terminates_when_llm_says_stop(self):
        engine = self._make_engine(decide_response={"command": "nmap -sV 10.0.0.1", "continue": False, "new_targets": []})
        engine.start_scan("10.0.0.0/24")
        # Only 1 depth ran
        assert engine.metrics["depth"] == 1

    def test_new_targets_added_to_live_ips(self):
        # LLM suggests a new target on depth 1, then says stop on depth 2
        responses = [
            {"command": "nmap -sV 10.0.0.1", "continue": True, "new_targets": ["10.0.1.0/24"]},
            {"command": "nmap -sV 10.0.1.0/24", "continue": False, "new_targets": []},
        ]
        engine = self._make_engine()
        engine.agent.decide = MagicMock(side_effect=responses)
        engine.start_scan("10.0.0.0/24")
        # Depth 2 port scan should include the new target
        second_call_args = engine._run_port_scan.call_args_list[1][0][0]
        assert "10.0.1.0/24" in second_call_args

    def test_hunter_runs_before_gap_check(self):
        """Critical targets should be hunter-scanned even when gap_report is empty."""
        engine = self._make_engine()

        def classify_with_critical(hosts):
            for h in hosts:
                h["criticality"] = "CRITICAL"
                h["type"] = "Database Server"
                h["metrics"] = []
            return hosts, [{"ip": h["target"], "type": "Database Server"} for h in hosts]

        engine._classify_hosts = MagicMock(side_effect=classify_with_critical)
        # Make all gaps already filled (high OS accuracy, versions present, scripts present)
        engine._run_port_scan = MagicMock(return_value=[
            _make_host("10.0.0.1", os_accuracy=95, ports=[
                _make_port(3306, version="MySQL 8.0",
                           scripts=[{"id": "mysql-info", "output": "..."}])
            ])
        ])
        engine.start_scan("10.0.0.0/24")
        engine._run_hunter.assert_called_once()


from unittest.mock import MagicMock, patch
from src.utils.exceptions import ReconesisAPIError, ReconesisParseError


class TestOodaStep:
    """Tests for the extracted _ooda_step method."""

    def _make_engine(self):
        from src.core.reconesis import ReconesisEngine
        engine = ReconesisEngine()
        engine._host_map = {
            "10.0.0.1": {
                "target": "10.0.0.1", "ports": [], "os": {"name": "Linux", "accuracy": 90},
                "type": "Generic Host", "criticality": "LOW",
            }
        }
        return engine

    def test_ooda_step_terminates_on_no_gaps(self):
        """When _compute_gaps returns [], _ooda_step returns a termination reason."""
        engine = self._make_engine()
        engine._host_map["10.0.0.1"]["ports"] = []  # no ports = no gaps
        with patch.object(engine, '_run_port_scan', return_value=[]), \
             patch.object(engine, '_classify_hosts', return_value=(list(engine._host_map.values()), [])), \
             patch.object(engine, '_update_scan_history'):
            reason, _ = engine._ooda_step(depth=1, prev_hash="abc")
        assert reason is not None  # terminated

    def test_ooda_step_terminates_on_hash_saturation(self):
        """When the new hash equals prev_hash, _ooda_step returns a termination reason."""
        engine = self._make_engine()
        mock_decision = {"command": "nmap -sS 10.0.0.1", "continue": False, "new_targets": []}
        with patch.object(engine, '_run_port_scan', return_value=[]), \
             patch.object(engine, '_classify_hosts', return_value=([], [])), \
             patch.object(engine, '_update_scan_history'), \
             patch.object(engine, '_compute_gaps', return_value=[{"ip": "10.0.0.1", "gaps": ["os_unknown"]}]), \
             patch.object(engine.agent, 'decide', return_value=mock_decision), \
             patch.object(engine, '_execute_and_merge'), \
             patch.object(engine.parser, 'compute_hash', return_value="same_hash"):
            reason, _ = engine._ooda_step(depth=1, prev_hash="same_hash")
        assert reason is not None


class TestOodaStepExceptions:
    """Tests for named exception handling in _ooda_step."""

    def _make_engine(self):
        from src.core.reconesis import ReconesisEngine
        engine = ReconesisEngine()
        engine._host_map = {}
        return engine

    def test_api_error_from_query_groq_caught_in_ooda(self):
        """ReconesisAPIError raised by decide is caught, returns api_error."""
        engine = self._make_engine()
        with patch.object(engine, '_run_port_scan', return_value=[]), \
             patch.object(engine, '_classify_hosts', return_value=([], [])), \
             patch.object(engine, '_update_scan_history'), \
             patch.object(engine, '_compute_gaps', return_value=[{"ip": "10.0.0.1", "gaps": ["os_unknown"]}]), \
             patch.object(engine.agent, 'decide', side_effect=ReconesisAPIError("api down")):
            reason, _ = engine._ooda_step(depth=2, prev_hash="")
        assert reason == "api_error"

    def test_parse_error_triggers_generate_strategy_fallback(self):
        """ReconesisParseError from decide() causes generate_strategy() to be called."""
        engine = self._make_engine()
        with patch.object(engine, '_run_port_scan', return_value=[]), \
             patch.object(engine, '_classify_hosts', return_value=([], [])), \
             patch.object(engine, '_update_scan_history'), \
             patch.object(engine, '_compute_gaps', return_value=[{"ip": "10.0.0.1", "gaps": ["os_unknown"]}]), \
             patch.object(engine.agent, 'decide', side_effect=ReconesisParseError("bad json")), \
             patch.object(engine.agent, 'generate_strategy', return_value="nmap -sS 10.0.0.0/24") as mock_gen, \
             patch.object(engine, '_execute_and_merge'), \
             patch.object(engine.parser, 'compute_hash', return_value="new_hash"):
            reason, _ = engine._ooda_step(depth=2, prev_hash="old_hash")
        mock_gen.assert_called_once()
        assert reason is None  # continued, not terminated

    def test_generate_strategy_failure_returns_strategy_fallback_failed(self):
        """If both decide() and generate_strategy() fail, _ooda_step returns strategy_fallback_failed."""
        engine = self._make_engine()
        with patch.object(engine, '_run_port_scan', return_value=[]), \
             patch.object(engine, '_classify_hosts', return_value=([], [])), \
             patch.object(engine, '_update_scan_history'), \
             patch.object(engine, '_compute_gaps', return_value=[{"ip": "10.0.0.1", "gaps": ["os_unknown"]}]), \
             patch.object(engine.agent, 'decide', side_effect=ReconesisParseError("bad json")), \
             patch.object(engine.agent, 'generate_strategy', side_effect=ReconesisAPIError("api down")):
            reason, _ = engine._ooda_step(depth=2, prev_hash="")
        assert reason == "strategy_fallback_failed"


class TestComputeGapsAdditional:
    def _make_engine(self):
        from src.core.reconesis import ReconesisEngine
        return ReconesisEngine()

    def test_empty_host_map_returns_no_gaps(self):
        engine = self._make_engine()
        engine._host_map = {}
        assert engine._compute_gaps() == []

    def test_host_with_no_ports_returns_os_gap(self):
        engine = self._make_engine()
        engine._host_map = {
            "10.0.0.1": {
                "target": "10.0.0.1",
                "ports": [],
                "os": {"name": "unknown", "accuracy": 0},
                "type": "Generic Host", "criticality": "LOW",
            }
        }
        gaps = engine._compute_gaps()
        assert len(gaps) == 1
        assert "os_unknown" in gaps[0]["gaps"]


class TestDecideForDepth:
    def _make_agent(self):
        with patch("src.core.agent.Config"):
            agent = GroqAgent.__new__(GroqAgent)
            agent.logger = MagicMock()
            agent._session = MagicMock()
            agent.api_url = "http://fake"
            agent.api_key = "fake"
            agent.model = "fake-model"
            return agent

    def _make_context(self, depth=1):
        return {
            "depth": depth,
            "depth_purpose": "Test purpose",
            "target_hosts": [],
            "hosts": [],
            "scan_history": [],
        }

    def _mock_groq_response(self, agent, payload):
        response = MagicMock()
        response.status_code = 200
        response.json.return_value = {
            "choices": [{"message": {"content": payload}, "finish_reason": "stop"}]
        }
        agent._session.post.return_value = response

    def test_depth1_returns_command(self):
        from src.core.agent import GroqAgent
        agent = self._make_agent()
        self._mock_groq_response(agent,
            '{"command": "nmap -sS 10.0.0.1", "rationale": "x", "continue": true, "new_targets": []}')
        ctx = self._make_context(depth=1)
        result = agent.decide_for_depth(ctx)
        assert result["command"] == "nmap -sS 10.0.0.1"
        assert result["continue"] is True

    def test_depth2_returns_command(self):
        from src.core.agent import GroqAgent
        agent = self._make_agent()
        self._mock_groq_response(agent,
            '{"command": "nmap -sV 10.0.0.2", "rationale": "y", "continue": false, "new_targets": []}')
        ctx = self._make_context(depth=2)
        result = agent.decide_for_depth(ctx)
        assert result["command"] == "nmap -sV 10.0.0.2"
        assert result["continue"] is False

    def test_depth3_returns_command(self):
        from src.core.agent import GroqAgent
        agent = self._make_agent()
        self._mock_groq_response(agent,
            '{"command": "nmap -sV --script http-title 10.0.0.3", "rationale": "z", "continue": false, "new_targets": []}')
        ctx = self._make_context(depth=3)
        result = agent.decide_for_depth(ctx)
        assert result["command"] == "nmap -sV --script http-title 10.0.0.3"

    def test_api_error_raises(self):
        from src.core.agent import GroqAgent
        from src.utils.exceptions import ReconesisAPIError
        agent = self._make_agent()
        agent._session.post.side_effect = Exception("network error")
        ctx = self._make_context(depth=1)
        with pytest.raises(ReconesisAPIError):
            agent.decide_for_depth(ctx)

    def test_parse_error_raises(self):
        from src.core.agent import GroqAgent
        from src.utils.exceptions import ReconesisParseError
        agent = self._make_agent()
        self._mock_groq_response(agent, "not json at all")
        ctx = self._make_context(depth=1)
        with pytest.raises(ReconesisParseError):
            agent.decide_for_depth(ctx)


class TestMiniLoop:
    def _make_engine(self):
        with patch("src.core.reconesis.NmapExecutor"), \
             patch("src.core.reconesis.GroqAgent"), \
             patch("src.core.reconesis.TOONParser"), \
             patch("src.core.reconesis.CriticalityAssessor"), \
             patch("src.core.reconesis.ExploitLookup"):
            engine = ReconesisEngine()
            engine._execute_and_merge = MagicMock()
            return engine

    def _make_decision(self, command="nmap -sS 10.0.0.1", cont=True, new_targets=None):
        return {"command": command, "rationale": "x", "continue": cont,
                "new_targets": new_targets or []}

    def test_exits_on_continue_false(self):
        engine = self._make_engine()
        engine.agent.decide_for_depth = MagicMock(
            return_value=self._make_decision(cont=False))
        engine.parser.compute_hash = MagicMock(return_value="hash1")
        engine._compute_gaps = MagicMock(return_value=[])
        ctx = {"depth": 1, "depth_purpose": "", "target_hosts": [],
               "hosts": [], "scan_history": []}
        engine._mini_loop(ctx)
        assert engine.agent.decide_for_depth.call_count == 1

    def test_exits_on_hash_saturation(self):
        engine = self._make_engine()
        engine.agent.decide_for_depth = MagicMock(
            return_value=self._make_decision(cont=True))
        engine.parser.compute_hash = MagicMock(return_value="same_hash")
        engine._compute_gaps = MagicMock(return_value=[])
        ctx = {"depth": 1, "depth_purpose": "", "target_hosts": [],
               "hosts": [], "scan_history": []}
        engine._mini_loop(ctx)
        assert engine.agent.decide_for_depth.call_count >= 1

    def test_exits_on_api_error(self):
        from src.utils.exceptions import ReconesisAPIError
        engine = self._make_engine()
        engine.agent.decide_for_depth = MagicMock(
            side_effect=ReconesisAPIError("boom"))
        engine._compute_gaps = MagicMock(return_value=[])
        ctx = {"depth": 1, "depth_purpose": "", "target_hosts": [],
               "hosts": [], "scan_history": []}
        engine._mini_loop(ctx)   # should not raise
        assert engine._execute_and_merge.call_count == 0

    def test_exits_after_max_sub_iterations(self):
        from src.utils.config import Config
        engine = self._make_engine()
        call_count = [0]
        def side_effect(ctx):
            call_count[0] += 1
            return self._make_decision(cont=True)
        engine.agent.decide_for_depth = MagicMock(side_effect=side_effect)
        engine.parser.compute_hash = MagicMock(side_effect=lambda x: str(call_count[0]))
        engine._compute_gaps = MagicMock(return_value=[])
        ctx = {"depth": 1, "depth_purpose": "", "target_hosts": [],
               "hosts": [], "scan_history": []}
        engine._mini_loop(ctx)
        assert call_count[0] == Config.MAX_SUB_ITERATIONS

    def test_seeds_new_targets_as_stubs(self):
        engine = self._make_engine()
        engine.agent.decide_for_depth = MagicMock(return_value=self._make_decision(
            cont=False, new_targets=["10.0.0.99"]))
        engine.parser.compute_hash = MagicMock(return_value="h1")
        engine._compute_gaps = MagicMock(return_value=[])
        ctx = {"depth": 1, "depth_purpose": "", "target_hosts": [],
               "hosts": [], "scan_history": []}
        engine._mini_loop(ctx)
        assert "10.0.0.99" in engine._host_map
        assert engine._host_map["10.0.0.99"]["status"] == "up"

    def test_inject_vulners_forwarded(self):
        engine = self._make_engine()
        engine.agent.decide_for_depth = MagicMock(
            return_value=self._make_decision(cont=False))
        engine.parser.compute_hash = MagicMock(return_value="h1")
        engine._compute_gaps = MagicMock(return_value=[])
        ctx = {"depth": 2, "depth_purpose": "", "target_hosts": [],
               "hosts": [], "scan_history": []}
        engine._mini_loop(ctx, inject_vulners=True)
        engine._execute_and_merge.assert_called_once_with(
            "nmap -sS 10.0.0.1", inject_vulners=True)

    def test_inject_vulners_false_by_default(self):
        engine = self._make_engine()
        engine.agent.decide_for_depth = MagicMock(
            return_value=self._make_decision(cont=False))
        engine.parser.compute_hash = MagicMock(return_value="h1")
        engine._compute_gaps = MagicMock(return_value=[])
        ctx = {"depth": 1, "depth_purpose": "", "target_hosts": [],
               "hosts": [], "scan_history": []}
        engine._mini_loop(ctx)  # inject_vulners not passed — defaults to False
        engine._execute_and_merge.assert_called_once_with(
            "nmap -sS 10.0.0.1", inject_vulners=False)


class TestRunDepth1Mapping:
    def _make_engine(self):
        with patch("src.core.reconesis.NmapExecutor"), \
             patch("src.core.reconesis.GroqAgent"), \
             patch("src.core.reconesis.TOONParser"), \
             patch("src.core.reconesis.CriticalityAssessor"), \
             patch("src.core.reconesis.ExploitLookup"):
            engine = ReconesisEngine()
            engine._mini_loop = MagicMock()
            return engine

    def test_calls_mini_loop_with_depth1(self):
        engine = self._make_engine()
        engine._host_map = {"10.0.0.1": _make_host("10.0.0.1")}
        engine._run_depth1_mapping(["10.0.0.1"])
        assert engine._mini_loop.called
        ctx = engine._mini_loop.call_args[0][0]
        assert ctx["depth"] == 1
        assert engine._mini_loop.call_args[1].get("inject_vulners") is False

    def test_passes_all_hosts_as_target_hosts(self):
        engine = self._make_engine()
        engine._host_map = {
            "10.0.0.1": _make_host("10.0.0.1"),
            "10.0.0.2": _make_host("10.0.0.2"),
        }
        engine._run_depth1_mapping(["10.0.0.1", "10.0.0.2"])
        ctx = engine._mini_loop.call_args[0][0]
        ips = [h["target"] for h in ctx["target_hosts"]]
        assert "10.0.0.1" in ips
        assert "10.0.0.2" in ips


class TestRunDepth2DeepDive:
    def _make_engine(self):
        with patch("src.core.reconesis.NmapExecutor"), \
             patch("src.core.reconesis.GroqAgent"), \
             patch("src.core.reconesis.TOONParser"), \
             patch("src.core.reconesis.CriticalityAssessor"), \
             patch("src.core.reconesis.ExploitLookup"):
            engine = ReconesisEngine()
            engine._mini_loop = MagicMock()
            return engine

    def test_calls_mini_loop_with_depth2_and_inject_vulners(self):
        engine = self._make_engine()
        engine._host_map = {"10.0.0.1": _make_host("10.0.0.1")}
        critical_high = [{"ip": "10.0.0.1", "type": "Database Server"}]
        engine._run_depth2_deep_dive(critical_high)
        assert engine._mini_loop.called
        ctx = engine._mini_loop.call_args[0][0]
        assert ctx["depth"] == 2
        assert engine._mini_loop.call_args[1].get("inject_vulners") is True

    def test_resolves_target_hosts_from_host_map(self):
        engine = self._make_engine()
        host = _make_host("10.0.0.1")
        engine._host_map = {"10.0.0.1": host}
        critical_high = [{"ip": "10.0.0.1", "type": "Database Server"}]
        engine._run_depth2_deep_dive(critical_high)
        ctx = engine._mini_loop.call_args[0][0]
        assert ctx["target_hosts"] == [host]


class TestRunDepth3Deepest:
    def _make_engine(self):
        with patch("src.core.reconesis.NmapExecutor"), \
             patch("src.core.reconesis.GroqAgent"), \
             patch("src.core.reconesis.TOONParser"), \
             patch("src.core.reconesis.CriticalityAssessor"), \
             patch("src.core.reconesis.ExploitLookup"):
            engine = ReconesisEngine()
            engine._mini_loop = MagicMock()
            return engine

    def test_calls_mini_loop_with_depth3_and_inject_vulners(self):
        engine = self._make_engine()
        engine._host_map = {"10.0.0.1": _make_host("10.0.0.1")}
        critical_high = [{"ip": "10.0.0.1", "type": "Mail Server"}]
        engine._run_depth3_deepest(critical_high)
        ctx = engine._mini_loop.call_args[0][0]
        assert ctx["depth"] == 3
        assert engine._mini_loop.call_args[1].get("inject_vulners") is True


