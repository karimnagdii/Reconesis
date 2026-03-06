
import subprocess
import logging
import re
from typing import Optional, Tuple


class NmapExecutor:
    def __init__(self):
        self.logger = logging.getLogger("NmapExecutor")

    def execute(self, command: str) -> Tuple[Optional[str], int]:
        """
        Executes an Nmap command and returns the XML output + packet count.
        Args:
            command (str): The full Nmap command line string.
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
                self.logger.error("Nmap produced no output.")
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

        # Fix --top-ports without a numeric argument
        # Common LLM error: "nmap --top-ports 192.168.1.1" (missing count)
        top_ports_match = re.search(r'--top-ports\s+(\S+)', command)
        if top_ports_match:
            value = top_ports_match.group(1)
            if not value.isdigit():
                self.logger.warning(
                    f"--top-ports had non-numeric value '{value}', inserting default 1000."
                )
                command = command.replace(
                    f"--top-ports {value}",
                    f"--top-ports 1000 {value}"
                )

        return command

