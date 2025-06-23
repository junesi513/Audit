import sys
from os import path
from pathlib import Path
import json
import os

from src.agent.agent import Agent
from src.llmtool.patcher.patch_generator import PatchGenerator
from src.tstool.analyzer.Java_TS_analyzer import JavaTSAnalyzer

class PatcherAgent(Agent):
    def __init__(self, **kwargs):
        super().__init__()
        self.project_path = kwargs.get('project_path')
        self.language = kwargs.get('language')
        self.model_name = kwargs.get('model_name')
        self.api_key = kwargs.get('api_key')
        self.prompt_path = kwargs.get('prompt_path')
        self.logger = kwargs.get('logger')
        self.tag = kwargs.get('tag')
        
        # Create a unique result directory for this agent run
        agent_name = self.__class__.__name__
        log_dir = kwargs.get('log_dir', 'log')
        self.result_dir = Path(log_dir) / f"{agent_name}-{self.tag}"
        self.result_dir.mkdir(parents=True, exist_ok=True)
        
        self.patcher = None
        self.input_dir = kwargs.get('input_dir')
        self.patcher_log = []

    def _get_file_content(self, file_path: str) -> str:
        """Reads the content of a file."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return f.read()
        except FileNotFoundError:
            self.logger.print_console(f"Error: File not found: {file_path}")
            return None
        except Exception as e:
            self.logger.print_console(f"Error reading file {file_path}: {e}")
            return None

    def _write_file_content(self, file_path: str, content: str):
        """Writes content to a file."""
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
        except Exception as e:
            self.logger.print_console(f"Error writing to file {file_path}: {e}")

    def start_scan(self):
        """
        Public method to start the patching process.
        """
        self.logger.print_console("PatcherAgent scan started.")
        self.run()

    def get_agent_state(self):
        """
        This agent does not maintain a state that needs to be saved.
        Fulfills the abstract method requirement.
        """
        return None

    def run(self):
        """
        Runs the patching process.
        """
        # 1. Load the detection report
        if not self.input_dir:
            self.logger.print_console("Error: --input_dir is required for the patcher agent.")
            return

        detect_report_path = os.path.join(self.input_dir, 'detect_info.json')
        if not os.path.exists(detect_report_path):
            self.logger.print_console(f"Error: Detection report not found at {detect_report_path}")
            self.logger.print_console("Please run the 'concolic' scan first to generate a detection report.")
            return
        
        with open(detect_report_path, 'r') as f:
            detect_data = json.load(f)

        # The report is a list of bug reports
        if not detect_data:
            self.logger.print_console("Error: The detection report is empty.")
            return

        bug_report = detect_data[0] # Take the first bug report from the list
        
        cwe_id = bug_report.get('bug_type', 'N/A')
        file_path = bug_report.get('file_path')
        function_name = bug_report.get('function_name')
        func_code = bug_report.get('function_code')
        start_line = bug_report.get('start_line')
        end_line = bug_report.get('end_line')

        if not all([file_path, function_name, func_code, start_line, end_line]):
            self.logger.print_console(f"Error: Bug report is missing required fields (file_path, function_name, etc.).")
            return
            
        self.logger.print_console(f"Loaded bug report for {cwe_id} in {file_path}")

        # 2. Initialize tools
        self.patcher = PatchGenerator(
            prompt_path=self.prompt_path,
            model_name=self.model_name,
            api_key=self.api_key,
            logger=self.logger,
            language=self.language
        )

        # 3. Generate the patch
        self.logger.print_console(f"Generating patch for function '{function_name}'...")
        response = self.patcher.run(
            bug_report=bug_report,
            func_code=func_code
        )
        patched_code = response.get_text().strip()

        # Log the interaction
        self.patcher_log.append({
            "prompt": self.patcher.prompt.get_user_prompt(
                func_code=func_code,
                bug_report=json.dumps(bug_report, indent=4)
            ),
            "response": patched_code,
        })

        if "```java" in patched_code:
            patched_code = patched_code.split("```java")[1].split("```")[0].strip()
        elif "```" in patched_code:
            patched_code = patched_code.split("```")[1].strip()

        self.logger.print_console("Successfully generated patched code.")
        
        # 4. Apply the patch to the file
        self.logger.print_console(f"Applying patch to {file_path}")
        original_file_content = self._get_file_content(file_path)
        if original_file_content is None:
            return # Error already logged
        
        # We now have start and end lines directly from the report
        lines = original_file_content.split('\n')
        
        # Reconstruct the file with the patched code
        new_content_lines = lines[:start_line - 1] + [patched_code] + lines[end_line:]
        new_file_content = '\n'.join(new_content_lines)

        self._write_file_content(file_path, new_file_content)
        self.logger.print_console(f"Successfully patched file: {file_path}")

        # 5. Save patch info
        patch_info = {
            "file_path": file_path,
            "function_name": function_name,
            "cwe_id": cwe_id,
            "original_code": func_code,
            "patched_code": patched_code,
            "llm_prompt": self.patcher_log[0]['prompt'],
            "llm_response": self.patcher_log[0]['response'],
        }
        patch_info_path = os.path.join(self.result_dir, 'patch_info.json')
        with open(patch_info_path, 'w') as f:
            json.dump(patch_info, f, indent=4)
        
        self.logger.print_console(f"Patch information saved to {patch_info_path}") 