import pytest
from src.utils.criticality import CriticalityAssessor

@pytest.fixture(scope="module")
def assessor():
    return CriticalityAssessor()

def _make_host(target="1.2.3.4", ports=None, os_name="unknown", os_acc=0, scripts_per_port=None):
    """Build a minimal TOON host dict for testing."""
    ports = ports or []
    result_ports = []
    for i, p in enumerate(ports):
        port_dict = {"port": p["port"], "protocol": "tcp", "service": p.get("service", ""),
                     "product": p.get("product", ""), "version": p.get("version", ""),
                     "auth_required": False, "scripts": []}
        if scripts_per_port and i < len(scripts_per_port):
            port_dict["scripts"] = scripts_per_port[i]
        result_ports.append(port_dict)
    return {"target": target, "status": "up", "os": {"name": os_name, "accuracy": os_acc},
            "ports": result_ports, "criticality": "LOW", "type": "Generic Host"}

def test_bundle_ip(assessor):
    host = _make_host(target="10.0.0.1")
    assessment = assessor.assess(host)
    bundle = assessor.build_evidence_bundle(host, assessment)
    assert bundle["ip"] == "10.0.0.1"

def test_bundle_os_unknown_becomes_null(assessor):
    host = _make_host(os_name="unknown", os_acc=0)
    assessment = assessor.assess(host)
    bundle = assessor.build_evidence_bundle(host, assessment)
    assert bundle["os"] is None

def test_bundle_os_known_preserved(assessor):
    host = _make_host(os_name="Linux 4.15", os_acc=85)
    assessment = assessor.assess(host)
    bundle = assessor.build_evidence_bundle(host, assessment)
    assert bundle["os"] == {"name": "Linux 4.15", "accuracy": 85}

def test_bundle_hostname_always_null(assessor):
    host = _make_host()
    assessment = assessor.assess(host)
    bundle = assessor.build_evidence_bundle(host, assessment)
    assert bundle["hostname"] is None

def test_bundle_scripts_flattened(assessor):
    scripts = [{"id": "http-title", "output": "My App"}, {"id": "http-auth", "output": "none"}]
    host = _make_host(ports=[{"port": 80, "service": "http"}], scripts_per_port=[scripts])
    assessment = assessor.assess(host)
    bundle = assessor.build_evidence_bundle(host, assessment)
    assert bundle["scripts"] == {"http-title": "My App", "http-auth": "none"}

def test_bundle_scripts_empty_when_no_scripts(assessor):
    host = _make_host(ports=[{"port": 80, "service": "http"}])
    assessment = assessor.assess(host)
    bundle = assessor.build_evidence_bundle(host, assessment)
    assert bundle["scripts"] == {}

def test_bundle_generic_host_top_score_zero(assessor):
    """When no profile matches, type is Generic Host and top_score must be 0."""
    host = _make_host(ports=[{"port": 9999, "service": "unknown"}])
    assessment = assessor.assess(host)
    assert assessment["type"] == "Generic Host"
    bundle = assessor.build_evidence_bundle(host, assessment)
    assert bundle["static"]["top_type"] == "Generic Host"
    assert bundle["static"]["top_score"] == 0

def test_bundle_runner_up_is_second_highest(assessor):
    """Runner-up must be the second-highest scoring named profile."""
    # Two distinct profiles must score so runner_up is meaningful (non-zero).
    # Port 5432 + postgresql drives Database Server; port 25 + smtp/postfix drives Mail Server.
    host = _make_host(ports=[
        {"port": 5432, "service": "postgresql", "product": "postgresql"},
        {"port": 25,   "service": "smtp",       "product": "postfix"},
    ])
    assessment = assessor.assess(host)
    bundle = assessor.build_evidence_bundle(host, assessment)
    # top should be Database Server; runner_up should be a named profile, not Generic Host
    assert bundle["static"]["top_type"] == "Database Server"
    runner_up = bundle["static"]["runner_up"]
    assert runner_up["type"] != "Generic Host"
    assert runner_up["score"] > 0

def test_bundle_ports_include_service_product_version(assessor):
    host = _make_host(ports=[{"port": 443, "service": "https", "product": "nginx", "version": "1.18"}])
    assessment = assessor.assess(host)
    bundle = assessor.build_evidence_bundle(host, assessment)
    assert len(bundle["ports"]) == 1
    p = bundle["ports"][0]
    assert p["port"] == 443
    assert p["service"] == "https"
    assert p["product"] == "nginx"
    assert p["version"] == "1.18"

def test_bundle_signals_from_assess_reasons(assessor):
    host = _make_host(ports=[{"port": 3306, "service": "mysql"}])
    assessment = assessor.assess(host)
    bundle = assessor.build_evidence_bundle(host, assessment)
    assert bundle["static"]["signals"] == assessment["reasons"]
