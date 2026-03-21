# src/utils/exceptions.py


class ReconesisAPIError(Exception):
    """Raised when the Groq API call fails or returns an error sentinel."""


class ReconesisParseError(Exception):
    """Raised when LLM response cannot be parsed as expected JSON."""
