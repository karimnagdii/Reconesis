# tests/test_executor_debug_events.py
import pytest
from unittest.mock import patch, MagicMock
from src.core.executor import NmapExecutor


@pytest.fixture
def executor_with_events():
    events = []
    ex = NmapExecutor(event_callback=lambda t, d: events.append((t, d)))
    ex.nmap_path = "/usr/bin/nmap"  # prevent _prepare_command from bailing early
    return ex, events


def _make_proc(returncode=0, stdout="<nmaprun></nmaprun>", stderr=""):
    proc = MagicMock()
    proc.returncode = returncode
    proc.stdout.read.return_value = stdout
    proc.stderr.read.return_value = stderr
    # Return None (not raise) so _wait_with_timeout exits on first iteration
    proc.wait.return_value = None
    return proc


def test_executor_cmd_id_starts_at_one():
    ex = NmapExecutor()
    assert ex._cmd_id == 1


def test_nmap_exec_emitted_before_subprocess(executor_with_events):
    ex, events = executor_with_events
    proc = _make_proc()
    with patch("subprocess.Popen", return_value=proc):
        ex.execute("nmap -sS 10.0.0.1 -T4")
    exec_events = [e for e in events if e[0] == "nmap_exec"]
    assert len(exec_events) == 1
    assert "nmap" in exec_events[0][1]["command"]
    assert exec_events[0][1]["cmd_id"] == 1
    assert exec_events[0][1]["inject_vulners"] is False


def test_nmap_result_emitted_after_subprocess(executor_with_events):
    ex, events = executor_with_events
    proc = _make_proc(stdout="<nmaprun></nmaprun>")
    with patch("subprocess.Popen", return_value=proc):
        ex.execute("nmap -sS 10.0.0.1 -T4")
    result_events = [e for e in events if e[0] == "nmap_result"]
    assert len(result_events) == 1
    assert result_events[0][1]["cmd_id"] == 1
    assert result_events[0][1]["had_output"] is True
    assert result_events[0][1]["exit_code"] == 0
    assert result_events[0][1]["packets"] == 0


def test_exec_and_result_share_cmd_id(executor_with_events):
    ex, events = executor_with_events
    proc = _make_proc()
    with patch("subprocess.Popen", return_value=proc):
        ex.execute("nmap -sS 10.0.0.1 -T4")
    exec_id = next(e[1]["cmd_id"] for e in events if e[0] == "nmap_exec")
    result_id = next(e[1]["cmd_id"] for e in events if e[0] == "nmap_result")
    assert exec_id == result_id


def test_cmd_id_increments_across_calls(executor_with_events):
    ex, events = executor_with_events
    proc = _make_proc()
    with patch("subprocess.Popen", return_value=proc):
        ex.execute("nmap -sS 10.0.0.1 -T4")
        ex.execute("nmap -sS 10.0.0.2 -T4")
    exec_ids = [e[1]["cmd_id"] for e in events if e[0] == "nmap_exec"]
    assert exec_ids == [1, 2]


def test_no_events_emitted_on_sanitization_failure():
    events = []
    ex = NmapExecutor(event_callback=lambda t, d: events.append((t, d)))
    ex.execute("not a valid command at all")
    debug_events = [e for e in events if e[0] in ("nmap_exec", "nmap_result")]
    assert debug_events == []


def test_nmap_result_had_output_false_on_empty_stdout(executor_with_events):
    ex, events = executor_with_events
    proc = _make_proc(stdout="", returncode=0)
    with patch("subprocess.Popen", return_value=proc):
        ex.execute("nmap -sS 10.0.0.1 -T4")
    result_events = [e for e in events if e[0] == "nmap_result"]
    assert result_events[0][1]["had_output"] is False
    assert result_events[0][1]["exit_code"] == 0
    assert result_events[0][1]["packets"] == 0


def test_inject_vulners_flag_in_nmap_exec_event(executor_with_events):
    ex, events = executor_with_events
    proc = _make_proc()
    with patch("subprocess.Popen", return_value=proc):
        ex.execute("nmap -sV 10.0.0.1 -T4", inject_vulners=True)
    exec_events = [e for e in events if e[0] == "nmap_exec"]
    assert exec_events[0][1]["inject_vulners"] is True


def test_nmap_result_emitted_on_timeout(executor_with_events):
    ex, events = executor_with_events
    proc = _make_proc()
    with patch("subprocess.Popen", return_value=proc):
        with patch.object(ex, "_wait_with_timeout", return_value=False):
            ex.execute("nmap -sS 10.0.0.1 -T4")
    result_events = [e for e in events if e[0] == "nmap_result"]
    assert len(result_events) == 1
    assert result_events[0][1]["exit_code"] == -1
    assert result_events[0][1]["had_output"] is False
    assert result_events[0][1]["packets"] == 0
