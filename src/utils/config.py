
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
