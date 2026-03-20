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
