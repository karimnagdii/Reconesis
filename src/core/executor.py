
import subprocess
import logging
import re
import shutil
import platform
from typing import Optional, Tuple


class NmapExecutor:
    def __init__(self):
        self.logger = logging.getLogger("NmapExecutor")
        self.nmap_path = self._find_nmap()

    def execute(self, command: str, inject_vulners: bool = False) -> Tuple[Optional[str], int]:
        """
        Executes an Nmap command and returns the XML output + packet count.
        Args:
            command (str): The full Nmap command string.
            inject_vulners (bool): If True, append --script vulners for CVE correlation.
                                   Should only be True for Hunter Mode (Phase 3) scans.
        Returns:
            Tuple[str | None, int]: (raw XML output, estimated packet count).
        """
        if not command or not command.strip():
            self.logger.error("Received empty command from agent — skipping execution.")
            return None, 0

        # Sanitize LLM-generated command before execution
        command = self._sanitize_command(command)
        if not command:
            self.logger.error("Command failed sanitization — skipping execution.")
            return None, 0

        # Inject vulners NSE script only when explicitly requested (Hunter Mode).
        # Injecting during broad Phase 2 scans causes NSE to probe the local Flask
        # server with binary payloads, flooding the log with spurious 400 errors.

        if inject_vulners and "vulners" not in command:
            # vulners NSE script requires -sV to have version data to query against
            if "-sV" not in command:
                command += " -sV"
                self.logger.info("Auto-injected '-sV' (required by vulners NSE script).")
            command += " --script vulners"
            self.logger.info("Auto-injected '--script vulners' for CVE correlation.")

        # Verify nmap is available
        if not self.nmap_path:
            self.logger.error(
                "Nmap not found in PATH. Please install nmap:\n"
                "  Windows: https://nmap.org/download.html\n"
                "  macOS: brew install nmap\n"
                "  Linux: sudo apt-get install nmap (or equivalent)"
            )
            return None, 0

        self.logger.info(f"Executing: {command}")
        try:
            # Ensure output is in XML format if not already specified
            if "-oX -" not in command:
                command += " -oX -"

            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                check=False,     # Don't raise exception on non-zero exit
                timeout=300      # 5 minute hard timeout
            )

            if result.returncode != 0:
                self.logger.warning(f"Nmap returned non-zero exit code: {result.returncode}")
                self.logger.warning(f"Stderr: {result.stderr}")

            # --- Extract packet count from stderr (Proposal §5: Traffic Volume) ---
            packets = self._parse_packet_count(result.stderr)

            if not result.stdout or not result.stdout.strip():
                self.logger.error(f"Nmap produced no output. Stderr: {result.stderr}")
                return None, packets

            return result.stdout, packets

        except subprocess.TimeoutExpired:
            self.logger.error("Nmap scan timed out after 300 seconds.")
            return None, 0
        except Exception as e:
            self.logger.error(f"Execution failed: {e}")
            return None, 0

    @staticmethod
    def _parse_packet_count(stderr: str) -> int:
        """
        Extracts packet count from Nmap's stderr output.
        Nmap typically prints lines like:
            'Raw packets sent: 2048 (90.112KB) | Rcvd: 1024 (40.960KB)'
        """
        if not stderr:
            return 0
        match = re.search(r'Raw packets sent:\s*(\d+)', stderr)
        if match:
            return int(match.group(1))
        return 0

    def _sanitize_command(self, command: str) -> str:
        """
        Validates and fixes common LLM-generated Nmap command mistakes.
        Returns the sanitized command, or empty string if unfixable.
        """
        command = command.strip()

        # Strip any leading text before 'nmap' (LLM sometimes adds prose)
        if "nmap" in command:
            command = command[command.index("nmap"):]
        else:
            self.logger.error("Command does not contain 'nmap'.")
            return ""

        # Remove dangerous shell operators that shouldn't be in an nmap command
        for dangerous in [";", "&&", "||", "|", ">", ">>", "<", "$("]:
            if dangerous in command:
                self.logger.warning(f"Stripped dangerous operator '{dangerous}' from command.")
                command = command.split(dangerous)[0].strip()

        # Fallback: if the AI used --top-ports despite prompt guidance, replace it with a
        # comprehensive explicit port list. --top-ports misses critical service ports
        # (MongoDB 27017, Redis 6379, BGP 179, etc.) and can't be safely supplemented
        # with -p on all nmap versions. This only fires if the AI ignores the prompt.
        SCAN_PORTS = (
            "21,22,23,25,53,80,110,111,135,139,143,161,179,389,443,445,"
            "465,512,513,514,587,636,873,993,995,1433,1521,2222,2375,"
            "3000,3306,3389,5432,5900,5984,6379,8080,8443,8888,9090,"
            "9200,9300,9600,11211,15672,27017,28017"
        )
        if "--top-ports" in command:
            command = re.sub(r'--top-ports\s+\S+', f'-p {SCAN_PORTS}', command)
            self.logger.warning(
                "AI used --top-ports despite prompt guidance — replaced with explicit port list."
            )

        # Enforce T4 timing for LAN scans when the LLM omits a timing template.
        # T4 is significantly faster than the T3 default with no reliability cost on LANs.
        if not re.search(r'-T\d', command):
            command += " -T4"

        return command

    def _find_nmap(self) -> Optional[str]:
        """
        Locates the nmap executable in the system PATH.
        Returns the full path to nmap, or None if not found.
        Handles Windows (.exe) and Unix variants.
        """
        # Try using shutil.which() — works on all platforms
        nmap_path = shutil.which("nmap")
        if nmap_path:
            self.logger.debug(f"Found nmap at: {nmap_path}")
            return nmap_path

        # Fallback: try nmap.exe on Windows
        if platform.system() == "Windows":
            nmap_path = shutil.which("nmap.exe")
            if nmap_path:
                self.logger.debug(f"Found nmap.exe at: {nmap_path}")
                return nmap_path

        self.logger.warning("Nmap executable not found in PATH")
        return None

