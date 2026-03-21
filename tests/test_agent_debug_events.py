import pytest
from unittest.mock import MagicMock, patch
from src.core.agent import GroqAgent


def test_agent_accepts_event_callback():
    cb = MagicMock()
    agent = GroqAgent(event_callback=cb)
    assert agent._emit is cb


def test_agent_default_callback_is_noop():
    agent = GroqAgent()
    # Should not raise
    agent._emit("test", {"key": "value"})


def test_agent_call_id_starts_at_one():
    agent = GroqAgent()
    assert agent._call_id == 1


def _make_mock_response(text="nmap -sS 10.0.0.1"):
    mock_response = MagicMock()
    mock_response.raise_for_status.return_value = None
    mock_response.json.return_value = {
        "choices": [{"message": {"content": text}, "finish_reason": "stop"}]
    }
    return mock_response


def test_query_groq_emits_ai_prompt_before_call():
    events = []
    agent = GroqAgent(event_callback=lambda t, d: events.append((t, d)))
    with patch.object(agent._session, "post", return_value=_make_mock_response()):
        agent._query_groq("sys", "user", phase="discovery")
    prompt_events = [e for e in events if e[0] == "ai_prompt"]
    assert len(prompt_events) == 1
    assert prompt_events[0][1]["phase"] == "discovery"
    assert prompt_events[0][1]["system_prompt"] == "sys"
    assert prompt_events[0][1]["user_prompt"] == "user"
    assert prompt_events[0][1]["call_id"] == 1


def test_query_groq_emits_ai_response_after_call():
    events = []
    agent = GroqAgent(event_callback=lambda t, d: events.append((t, d)))
    with patch.object(agent._session, "post", return_value=_make_mock_response("nmap -sS 1.2.3.4")):
        agent._query_groq("sys", "user", phase="depth1")
    response_events = [e for e in events if e[0] == "ai_response"]
    assert len(response_events) == 1
    assert response_events[0][1]["call_id"] == 1
    assert response_events[0][1]["phase"] == "depth1"
    assert "nmap" in response_events[0][1]["raw_response"]


def test_query_groq_prompt_before_response_order():
    events = []
    agent = GroqAgent(event_callback=lambda t, d: events.append((t, d)))
    with patch.object(agent._session, "post", return_value=_make_mock_response()):
        agent._query_groq("sys", "user", phase="classification")
    types = [e[0] for e in events]
    assert types.index("ai_prompt") < types.index("ai_response")


def test_call_id_increments_across_calls():
    events = []
    agent = GroqAgent(event_callback=lambda t, d: events.append((t, d)))
    with patch.object(agent._session, "post", return_value=_make_mock_response()):
        agent._query_groq("sys", "user1", phase="depth1")
        agent._query_groq("sys", "user2", phase="depth2")
    prompt_ids = [e[1]["call_id"] for e in events if e[0] == "ai_prompt"]
    assert prompt_ids == [1, 2]


def test_prompt_and_response_share_call_id():
    events = []
    agent = GroqAgent(event_callback=lambda t, d: events.append((t, d)))
    with patch.object(agent._session, "post", return_value=_make_mock_response()):
        agent._query_groq("sys", "user", phase="reporting")
    prompt_id = next(e[1]["call_id"] for e in events if e[0] == "ai_prompt")
    response_id = next(e[1]["call_id"] for e in events if e[0] == "ai_response")
    assert prompt_id == response_id


def test_call_id_advances_after_failed_call():
    events = []
    agent = GroqAgent(event_callback=lambda t, d: events.append((t, d)))
    # First call: simulate HTTP exception (raises, no ai_response)
    with patch.object(agent._session, "post", side_effect=Exception("connection failed")):
        try:
            agent._query_groq("sys", "fail", phase="depth1")
        except Exception:
            pass
    # Second call: succeeds
    with patch.object(agent._session, "post", return_value=_make_mock_response("nmap -sS 1.1.1.1")):
        agent._query_groq("sys", "user2", phase="depth2")
    prompt_ids = [e[1]["call_id"] for e in events if e[0] == "ai_prompt"]
    response_ids = [e[1]["call_id"] for e in events if e[0] == "ai_response"]
    assert prompt_ids == [1, 2]       # two prompts emitted, each with distinct id
    assert response_ids == [2]        # only one response (call #2 succeeded)
