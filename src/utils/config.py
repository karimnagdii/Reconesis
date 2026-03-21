
import os
import logging
import requests
from dotenv import load_dotenv

load_dotenv()


class Config:
    # LLM Settings — uses a real Groq model
    GROQ_API_URL = os.getenv("GROQ_API_URL", "https://api.groq.com/openai/v1/chat/completions")
    GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
    GROQ_MODEL = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")

    # Scanning Settings
    DEFAULT_TIMEOUT = 300   # 5 minutes per scan
    MAX_SUB_ITERATIONS = 5  # hard cap on mini-loop passes per depth

    # Criticality Thresholds
    # Ports that trigger classification as high-value assets (proposal §4.3.2)
    CRITICAL_PORTS = {22, 23, 25, 53, 80, 110, 143, 443, 1433, 3306, 3389, 5432, 5900, 21, 8443}
    CRITICAL_KEYWORDS = [
        "ssh", "telnet", "http", "https", "mysql", "postgresql",
        "mssql", "rdp", "vnc", "ftp", "smtp", "imap", "pop3", "domain"
    ]


def validate_config():
    """
    Validates critical Reconesis configuration before scanning starts.
    Checks Groq API key and tests connectivity.
    Returns (is_valid, error_message) tuple.
    """
    logger = logging.getLogger("ConfigValidator")

    # Check API key exists
    if not Config.GROQ_API_KEY or not Config.GROQ_API_KEY.strip():
        msg = (
            "❌ Groq API key not configured.\n"
            "Please set GROQ_API_KEY in your .env file or environment variables.\n"
            "Get a free API key from: https://console.groq.com/keys"
        )
        logger.error(msg)
        return False, msg

    # Test API connectivity with a simple query
    logger.info("Testing Groq API connectivity...")
    headers = {
        "Authorization": f"Bearer {Config.GROQ_API_KEY}",
        "Content-Type": "application/json"
    }
    payload = {
        "model": Config.GROQ_MODEL,
        "messages": [
            {"role": "user", "content": "Say 'ok'"}
        ]
    }

    try:
        response = requests.post(Config.GROQ_API_URL, headers=headers, json=payload, timeout=10)
        if response.status_code == 401:
            msg = "❌ Groq API authentication failed. Invalid or expired API key."
            logger.error(msg)
            return False, msg
        elif response.status_code == 403:
            msg = "❌ Groq API access denied. Check your API key permissions."
            logger.error(msg)
            return False, msg
        elif response.status_code >= 400:
            error_detail = response.text[:200]
            msg = f"❌ Groq API error ({response.status_code}): {error_detail}"
            logger.error(msg)
            return False, msg

        logger.info("✓ Groq API connectivity verified")
        return True, ""

    except requests.exceptions.Timeout:
        msg = "❌ Groq API request timed out. Check your network connection."
        logger.error(msg)
        return False, msg
    except requests.exceptions.RequestException as e:
        msg = f"❌ Groq API connection failed: {str(e)}"
        logger.error(msg)
        return False, msg
