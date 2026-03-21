import json
import pytest
from unittest.mock import patch, MagicMock
from src.core.agent import GroqAgent

agent = GroqAgent()

VALID_RESPONSE = json.dumps([
    {"ip": "1.2.3.4", "type": "Database Server", "criticality": "CRITICAL",
     "reasoning": "PostgreSQL on port 5432"},
    {"ip": "1.2.3.5", "type": "Generic Host", "criticality": "LOW",
     "reasoning": "UPS management interface"},
])

def _mock_query(response_text, finish_reason="stop"):
    return patch.object(agent, "_query_groq", return_value=(response_text, finish_reason))

def test_classify_returns_list_on_valid_json():
    bundles = [{"ip": "1.2.3.4"}, {"ip": "1.2.3.5"}]
    with _mock_query(VALID_RESPONSE):
        result = agent.classify_hosts(bundles)
    assert len(result) == 2
    assert result[0]["ip"] == "1.2.3.4"
    assert result[0]["criticality"] == "CRITICAL"

def test_classify_returns_empty_on_invalid_json():
    bundles = [{"ip": "1.2.3.4"}]
    with _mock_query("not valid json at all"):
        result = agent.classify_hosts(bundles)
    assert result == []

def test_classify_returns_empty_on_api_error():
    bundles = [{"ip": "1.2.3.4"}]
    with _mock_query("", "error"):
        result = agent.classify_hosts(bundles)
    assert result == []

def test_classify_returns_empty_on_exception():
    bundles = [{"ip": "1.2.3.4"}]
    with patch.object(agent, "_query_groq", side_effect=Exception("boom")):
        result = agent.classify_hosts(bundles)
    assert result == []

def test_classify_calls_query_groq_with_correct_params():
    bundles = [{"ip": "1.2.3.4"}]
    with patch.object(agent, "_query_groq", return_value=(VALID_RESPONSE, "stop")) as mock_q:
        agent.classify_hosts(bundles)
    call_kwargs = mock_q.call_args
    assert call_kwargs.kwargs.get("timeout") == 120
    assert call_kwargs.kwargs.get("temperature") == 0
    assert call_kwargs.kwargs.get("max_tokens") == 4096

def test_classify_user_prompt_is_dialect_format():
    bundles = [{"ip": "1.2.3.4", "ports": []}]
    with patch.object(agent, "_query_groq", return_value=(VALID_RESPONSE, "stop")) as mock_q:
        agent.classify_hosts(bundles)
    user_prompt = mock_q.call_args.args[1]
    # Dialect format: IP appears on line 1, not wrapped in JSON
    assert "1.2.3.4" in user_prompt
    assert not user_prompt.startswith("[")  # not a JSON array


class TestSelectSystemPrompt:
    def setup_method(self):
        self.agent = GroqAgent()

    def test_known_type_database(self):
        result = self.agent._select_system_prompt("hunter", {"database server"})
        assert result == self.agent._SYSTEM_PROMPTS["hunter_database"]

    def test_unknown_type_falls_back_to_generic(self):
        result = self.agent._select_system_prompt("hunter", {"unknown device"})
        assert result == self.agent._SYSTEM_PROMPTS["hunter_generic"]

    def test_mixed_case_type_matched(self):
        result = self.agent._select_system_prompt("hunter", {"mail server"})
        assert result == self.agent._SYSTEM_PROMPTS["hunter_mail"]


class TestBuildHunterPrompt:
    def test_output_contains_dialect_ring(self):
        from src.core.agent import _build_hunter_prompt, _DIALECT_RING
        result = _build_hunter_prompt("Database Server", "enumerate", "mysql-info")
        assert _DIALECT_RING in result

    def test_output_contains_output_rule(self):
        from src.core.agent import _build_hunter_prompt
        result = _build_hunter_prompt("Database Server", "enumerate", "mysql-info")
        assert "Output ONLY a single, valid nmap command" in result

    def test_output_contains_asset_type_and_scripts(self):
        from src.core.agent import _build_hunter_prompt
        result = _build_hunter_prompt("Mail Server", "verify", "smtp-open-relay")
        assert "Mail Server" in result
        assert "smtp-open-relay" in result


class TestQueryGroqUsesSession:
    def test_session_post_called_not_requests_post(self):
        """M-5: verify self._session.post is used, not requests.post directly."""
        agent = GroqAgent()
        mock_response = MagicMock()
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {
            "choices": [{"message": {"content": "nmap -sS 10.0.0.0/24"}, "finish_reason": "stop"}]
        }
        with patch.object(agent._session, "post", return_value=mock_response) as mock_post:
            result, reason = agent._query_groq("sys", "user")
        mock_post.assert_called_once()
        assert result == "nmap -sS 10.0.0.0/24"
