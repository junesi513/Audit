import os
import json
import difflib
from pathlib import Path
from src.agent.agent import Agent
from src.llmtool.patcher.patch_generator import PatchGenerator
from src.ui.logger import Logger

class PatcherAgent(Agent):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.project_path = kwargs.get('project_path')
        self.language = kwargs.get('language')
        self.model_name = kwargs.get('model_name', "gemini-1.5-pro-latest")
        self.api_key = kwargs.get('api_key')
        self.prompt_path = kwargs.get('prompt_path')
        self.tag = kwargs.get('tag')
        
        agent_name = self.__class__.__name__
        log_dir = kwargs.get('log_dir', 'log')
        self.result_dir = Path(log_dir) / f"{agent_name}-{self.tag}"
        self.result_dir.mkdir(parents=True, exist_ok=True)
        log_file = self.result_dir / "agent.log"
        self.logger = Logger(agent_name, str(log_file))
        
        self.input_dir = kwargs.get('input_dir')
        self.bug_reports = []
        self.patch_info = {}

    def _get_file_content(self, file_path: str) -> str:
        """Reads the content of a file."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return f.read()
        except FileNotFoundError:
            self.logger.print_console(f"Error: File not found at {file_path}", "error")
            return None
        except Exception as e:
            self.logger.print_console(f"Error reading file {file_path}: {e}", "error")
            return None
    
    def _write_file_content(self, file_path: str, content: str):
        """Writes content to a file."""
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
        except IOError as e:
            self.logger.print_console(f"Error writing to file {file_path}: {e}", "error")

    def _load_bug_reports(self):
        """Loads bug reports from a file."""
        try:
            report_path = Path(self.input_dir) / 'bug_report.json'
            if not report_path.exists():
                self.logger.print_console(f"Error: Detection report not found at {report_path}", "error")
                self.logger.print_console("Please run the 'concolic' scan first to generate a detection report.", "error")
                return False
            
            with open(report_path, 'r') as f:
                data = json.load(f)

            if not data:
                self.logger.print_console("Error: The detection report is empty.", "error")
                return False

            self.bug_reports = [data]
            for report in self.bug_reports:
                self.logger.print_console(f"Loaded bug report for {report['cwe_id']} in {report['file_path']}")
            return True
        except Exception as e:
            self.logger.print_console(f"Error loading or parsing bug report: {e}", "error")
            return False
    
    def _create_human_readable_report(self, bug_report: dict) -> str:
        cwe_explanations = {
            "CWE-502": (
                "Deserialization of Untrusted Data",
                "The function deserializes data from an untrusted source without proper validation. "
                "An attacker can manipulate the serialized data to instantiate arbitrary classes, "
                "which can lead to denial of service, data tampering, or remote code execution.",
                "The fix requires validating the type information before the actual deserialization occurs. "
                "A common and effective pattern is to use a whitelist of allowed classes. "
                "If the type being deserialized is not on the whitelist, the operation should be aborted."
            )
        }

        cwe_id = bug_report['cwe_id']
        if cwe_id in cwe_explanations:
            title, vulnerability, fix_strategy = cwe_explanations[cwe_id]
            report_str = (
                f"- **Vulnerability Type:** {title} ({cwe_id})\\n"
                f"- **Problem:** {vulnerability}\\n"
                f"- **Suggested Fix:** {fix_strategy}"
            )
        else:
            report_str = f"- **Vulnerability Type:** {cwe_id}\\n- **Problem:** An unspecified vulnerability has been detected in the function."
        
        return report_str

    def run(self):
        self.logger.print_console("PatcherAgent scan started.")
        if not self._load_bug_reports():
            return

        for bug_report in self.bug_reports:
            self.logger.print_console(f"Generating patch for function '{bug_report['function_name']}'...")
            
            patch_generator = PatchGenerator(
                language=self.language,
                model_name=self.model_name,
                api_key=self.api_key
            )

            human_readable_report = self._create_human_readable_report(bug_report)

            llm_output = patch_generator.generate(
                function_code=bug_report['function_code'],
                bug_report=human_readable_report
            )
            
            if not llm_output.is_valid:
                self.logger.print_console(f"Failed to generate patch for {bug_report['file_path']}: {llm_output.error_message}", "error")
                continue

            patched_code = patch_generator.get_text(llm_output).strip()
            
            if patched_code.startswith("```java"):
                patched_code = patched_code[len("```java"):].strip()
            if patched_code.startswith("```"):
                patched_code = patched_code[len("```"):].strip()
            if patched_code.endswith("```"):
                patched_code = patched_code[:-len("```")].strip()

            self.logger.print_console("Successfully generated patched code.")
            
            self.patch_info[bug_report['file_path']] = {
                'function_name': bug_report['function_name'],
                'cwe_id': bug_report['cwe_id'],
                'original_code': bug_report['function_code'],
                'patched_code': patched_code,
            }

            self._show_diff(bug_report['function_code'], patched_code)
            # self._apply_patch(bug_report, patched_code)
        
        self._save_patch_info()

    def _show_diff(self, original_code, patched_code):
        self.logger.print_console("--- SUGGESTED PATCH ---")
        diff = difflib.unified_diff(
            original_code.splitlines(keepends=True),
            patched_code.splitlines(keepends=True),
            fromfile='original',
            tofile='patched',
        )
        for line in diff:
            self.logger.print_console(line.rstrip('\\n'))
        self.logger.print_console("-----------------------")

    def _apply_patch(self, bug_report: dict, patched_code: str):
        """Applies the patch to the file."""
        file_path = bug_report['file_path']
        self.logger.print_console(f"Applying patch to {file_path}")
        original_file_content = self._get_file_content(file_path)
        
        if original_file_content is None:
            self.logger.print_console(f"Cannot apply patch, original file content of {file_path} is missing.", "error")
            return

        lines = original_file_content.splitlines(True) # Keep line endings
        
        start_line = bug_report['start_line']
        end_line = bug_report['end_line']
        
        if not (0 < start_line <= len(lines) and 0 < end_line <= len(lines)):
            self.logger.print_console(f"Error: Line numbers [{start_line}-{end_line}] are out of bounds for file {file_path}.", "error")
            return
        
        new_content_lines = lines[:start_line - 1] + [patched_code + '\n'] + lines[end_line:]
        new_file_content = "".join(new_content_lines)

        self._write_file_content(file_path, new_file_content)
        self.logger.print_console(f"Successfully patched file: {file_path}")

    def _save_patch_info(self):
        """Saves patch information to a file."""
        if not self.patch_info:
            return 
        patch_info_path = self.result_dir / 'patch_info.json'
        with open(patch_info_path, 'w') as f:
            json.dump(self.patch_info, f, indent=4)
        
        self.logger.print_console(f"Patch information saved to {patch_info_path}")

    def get_agent_state(self):
        return None 