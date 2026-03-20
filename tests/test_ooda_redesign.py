import pytest
from unittest.mock import MagicMock, patch
from src.core.reconesis import ReconesisEngine


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
