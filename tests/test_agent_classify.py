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

def test_classify_user_prompt_is_compact_json():
    bundles = [{"ip": "1.2.3.4", "ports": []}]
    with patch.object(agent, "_query_groq", return_value=(VALID_RESPONSE, "stop")) as mock_q:
        agent.classify_hosts(bundles)
    user_prompt = mock_q.call_args.args[1]
    # Compact JSON has no spaces after separators
    assert "  " not in user_prompt  # no pretty-print indentation
    parsed = json.loads(user_prompt)
    assert parsed[0]["ip"] == "1.2.3.4"
