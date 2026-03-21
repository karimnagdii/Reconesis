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
