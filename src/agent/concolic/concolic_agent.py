import json
import subprocess
from pathlib import Path
import pprint

from src.agent.agent import Agent
from src.llmtool.concolic.hypothesis_generator import HypothesisGenerator
from src.llmtool.concolic.semgrep_generator import SemgrepGenerator
from src.memory.report.bug_report import BugReport
from src.tstool.analyzer import JavaTSAnalyzer
from src.ui.logger import Logger

class ConcolicAgent(Agent):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.project_path = kwargs.get('project_path')
        self.target_function = kwargs.get('target_function')
        self.language = kwargs.get('language')
        self.model_name = kwargs.get('model_name', "gemini-1.5-pro-latest")
        self.api_key = kwargs.get('api_key')
        self.tag = kwargs.get('tag')
        self.cwe_id = "CWE-502"  # Hardcoded for now for this specific vulnerability
        
        agent_name = self.__class__.__name__
        log_dir = kwargs.get('log_dir', 'log')
        self.result_dir = Path(log_dir) / f"{agent_name}-{self.tag}"
        self.result_dir.mkdir(parents=True, exist_ok=True)
        log_file = self.result_dir / "agent.log"
        self.logger = Logger(agent_name, str(log_file))
        
        self.hypothesis_generator = HypothesisGenerator(
            model_name=self.model_name,
            language=self.language,
            api_key=self.api_key
        )
        self.semgrep_generator = SemgrepGenerator(
            language=self.language,
            model_name=self.model_name,
            api_key=self.api_key
        )
        
    def _get_analyzer(self):
        try:
            ext = self._get_file_extension()
            if not ext: return None
            
            files_with_ext = list(Path(self.project_path).rglob(f'*.{ext}'))
            if not files_with_ext:
                self.logger.print_console(f"No files with extension *.{ext} found.", "error")
                return None
            
            self.logger.print_console(f"Found {len(files_with_ext)} files.")
            code_in_files = {str(f): f.read_text() for f in files_with_ext}

            if self.language.lower() == 'java':
                return JavaTSAnalyzer(code_in_files=code_in_files, language_name=self.language.capitalize())
            
            # Other languages are not supported in this simplified agent
            self.logger.print_console(f"Language '{self.language}' is not supported in this context.", "error")
            return None
        except Exception as e:
            self.logger.print_console(f"Error creating analyzer: {e}", "error")
            return None

    def _get_file_extension(self) -> str:
        # Simplified to only support Java for this agent's purpose
        if self.language.lower() == 'java':
            return 'java'
        self.logger.print_console(f"Language '{self.language}' is not supported.", "error")
        return None

    def _run_semgrep_validation(self, semgrep_rule: str, file_path: str) -> dict | None:
        rule_path = self.result_dir / "semgrep_rule.yml"
        with open(rule_path, "w") as f:
            f.write(semgrep_rule)
            
        try:
            completed_process = subprocess.run(
                ["semgrep", "-c", str(rule_path), file_path, "--json"],
                capture_output=True,
                text=True,
                check=False # Do not raise exception for non-zero exit codes (e.g., when findings are present)
            )
            
            if completed_process.returncode not in [0, 1]: # 0 for no findings, 1 for findings
                self.logger.print_console(f"Semgrep failed with return code {completed_process.returncode}:\n{completed_process.stderr}", "error")
                return None
            
            output_json = json.loads(completed_process.stdout)
            # Return the findings if any exist
            return output_json if output_json.get("results") else None
            
        except FileNotFoundError:
            self.logger.print_console("`semgrep` command not found. Please ensure it is installed.", "error")
            return None
        except json.JSONDecodeError:
            self.logger.print_console(f"Failed to parse Semgrep JSON output.", "error")
            return None
        except Exception as e:
            self.logger.print_console(f"An unexpected error occurred during Semgrep validation: {e}", "error")
            return None

    def run(self):
        if self.target_function:
            self.logger.print_console(f"Start Concolic Scanning for function '{self.target_function}'...")
        else:
            self.logger.print_console(f"Start Concolic Scanning for all functions...")

        analyzer = self._get_analyzer()
        if not analyzer: return

        if self.target_function:
            functions_to_analyze = [analyzer.find_function_by_name(self.target_function)]
            if not functions_to_analyze[0]:
                self.logger.print_console(f"Target function '{self.target_function}' not found.")
                return
        else:
            functions_to_analyze = analyzer.function_env.values()
        
        vulnerability_found_count = 0
        
        for func_info in functions_to_analyze:
            if not func_info: continue

            self.logger.print_console(f"Analyzing function: {func_info.function_name} in {func_info.file_path}")

            self.logger.print_console(f"Generating vulnerability hypothesis for: {func_info.function_name}")
            llm_output = self.hypothesis_generator.generate(function_code=func_info.function_code)
            
            if not llm_output.is_valid:
                self.logger.print_console(f"Hypothesis generation failed: {llm_output.error_message}", "error")
                continue
            
            hypothesis_json = llm_output.output
            vulnerability_hypothesis = hypothesis_json.get('vulnerability_hypothesis', '')

            if not vulnerability_hypothesis:
                self.logger.print_console(f"Hypothesis generation failed for function '{func_info.function_name}': Hypothesis is empty.")
                continue
            
            self.logger.print_console("Generating Semgrep rule...")
            semgrep_rule_str = self.semgrep_generator.generate(
                function_code=func_info.function_code,
                vulnerability_hypothesis=vulnerability_hypothesis
            )
            if not semgrep_rule_str:
                self.logger.print_console("Semgrep rule generation failed.", "error")
                continue
            
            semgrep_rule = self.semgrep_generator.get_rule(semgrep_rule_str)
            if not semgrep_rule:
                self.logger.print_console(f"Skipping Semgrep validation for function '{func_info.function_name}' due to rule generation failure.")
                continue

            self.logger.print_console(f"Forcing Semgrep validation on {func_info.file_path}...")
            semgrep_results = self._run_semgrep_validation(semgrep_rule, func_info.file_path)

            if semgrep_results:
                self.logger.print_console(f"Hypothesis VALIDATED for function '{func_info.function_name}'! Vulnerability confirmed.")
                vulnerability_found_count += 1
                
                # Defensive coding for report generation
                cwe_id = "CWE-UNKNOWN"
                if isinstance(hypothesis_json, dict):
                    cwe_id = hypothesis_json.get("CWE_ID", "CWE-UNKNOWN")
                
                report_details = {
                    "semgrep_findings": semgrep_results.get("results", [])
                }

                report = BugReport(
                    cwe_id=cwe_id,
                    file_path=func_info.file_path,
                    function_name=func_info.function_name,
                    start_line=func_info.start_line_number,
                    end_line=func_info.end_line_number,
                    function_code=func_info.function_code,
                    language=self.language,
                    details=report_details
                )
                report.dump(self.result_dir, f"bug_report_{func_info.function_name}.json")
            else:
                self.logger.print_console(f"Hypothesis REJECTED for function '{func_info.function_name}'.")

        self.logger.print_console(f"Scan finished. {vulnerability_found_count} bug(s) were detected.")

    def get_agent_state(self):
        return None

# Add a check for the existence of semgrep directory
if not Path("src/semgrep").exists():
    # This is a fallback for the ModuleNotFoundError, not a perfect solution
    class SemgrepAnalyzer:
        def __init__(self, *args, **kwargs): pass
        def run_semgrep_for_cwe(self, *args, **kwargs): return []
else:
    from src.semgrep.semgrep_analyzer import SemgrepAnalyzer 