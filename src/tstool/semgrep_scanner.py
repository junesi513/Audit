import subprocess
import json
from pathlib import Path

from src.ui.logger import ui_logger

class SemgrepScanner:
    def __init__(self):
        self.semgrep_path = "/home/ace4_sijune/.local/bin/semgrep"

    def run(self, rule_id: str, target_path: str) -> dict:
        """
        Runs a specific Semgrep rule on a target file or directory.

        Args:
            rule_id: The ID of the Semgrep rule to use (without the .yml extension).
            target_path: The file or directory to scan.

        Returns:
            A dictionary containing the parsed Semgrep results, including
            whether the target was reachable.
        """
        rule_file = f"src/semgrep_rules/{rule_id}.yml"
        if not Path(rule_file).exists():
            ui_logger.print_console(f"Semgrep rule file not found: {rule_file}", "error")
            return {"error": "Rule file not found", "is_reachable": "NOT_REACHABLE"}

        command = [
            self.semgrep_path,
            "scan",
            "--config",
            rule_file,
            "--json",
            target_path,
        ]

        ui_logger.print_console(f"Running Semgrep command: {' '.join(command)}", "info")

        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=False  # Do not raise exception for non-zero exit codes
            )

            if result.returncode > 1: # 0 for no findings, 1 for findings, >1 for errors
                ui_logger.print_console(f"Semgrep scan failed with exit code {result.returncode}", "error")
                ui_logger.print_console(f"Stderr: {result.stderr}", "error")
                return {"error": result.stderr, "is_reachable": "NOT_REACHABLE"}
            
            try:
                json_output = json.loads(result.stdout)
                is_reachable = "REACHABLE" if json_output["results"] else "NOT_REACHABLE"
                json_output["is_reachable"] = is_reachable
                return json_output
            except json.JSONDecodeError:
                ui_logger.print_console("Failed to decode Semgrep JSON output.", "error")
                ui_logger.print_console(f"Raw output: {result.stdout}", "debug")
                return {"error": "JSONDecodeError", "is_reachable": "NOT_REACHABLE"}

        except FileNotFoundError:
            ui_logger.print_console("Semgrep command not found. Please ensure Semgrep is installed and in your PATH.", "error")
            return {"error": "Semgrep not found", "is_reachable": "NOT_REACHABLE"}
        except Exception as e:
            ui_logger.print_console(f"An unexpected error occurred during Semgrep scan: {e}", "error")
            return {"error": str(e), "is_reachable": "NOT_REACHABLE"} 