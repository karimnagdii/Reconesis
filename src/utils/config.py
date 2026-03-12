
import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    # LLM Settings — uses a real Groq model
    GROQ_API_URL = os.getenv("GROQ_API_URL", "https://api.groq.com/openai/v1/chat/completions")
    GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
    GROQ_MODEL = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")

    # Scanning Settings
    DEFAULT_TIMEOUT = 300   # 5 minutes per scan
    MAX_DEPTH = 3           # Proposal §4.3.4: max recursion depth before termination

    # Criticality Thresholds
    # Ports that trigger classification as high-value assets (proposal §4.3.2)
    CRITICAL_PORTS = {22, 23, 25, 53, 80, 110, 143, 443, 1433, 3306, 3389, 5432, 5900, 21, 8443}
    CRITICAL_KEYWORDS = [
        "ssh", "telnet", "http", "https", "mysql", "postgresql",
        "mssql", "rdp", "vnc", "ftp", "smtp", "imap", "pop3", "domain"
    ]

    # Ground Truth for Demo Lab (proposal §5: Decision Accuracy)
    # Maps IP → expected classification for accuracy measurement.
    # When scanning networks outside the demo lab, this is ignored and
    # the system falls back to ratio-based metrics.
    GROUND_TRUTH = {
        "172.20.0.10": {"type": "Database Server", "criticality": "CRITICAL"},
        "172.20.0.11": {"type": "Mail Server", "criticality": "CRITICAL"},
        "172.20.0.12": {"type": "Web Server/Admin Console", "criticality": "MEDIUM"},
        "172.20.0.13": {"type": "Generic Host", "criticality": "LOW"},
        "172.20.0.14": {"type": "Router", "criticality": "CRITICAL"},
        "172.20.0.15": {"type": "Firewall", "criticality": "CRITICAL"},
        "172.20.0.20": {"type": "Generic Host", "criticality": "LOW"},
        "172.20.0.21": {"type": "Generic Host", "criticality": "LOW"},
        "172.20.0.22": {"type": "Generic Host", "criticality": "LOW"},
        "172.20.0.23": {"type": "Generic Host", "criticality": "LOW"},
    }
