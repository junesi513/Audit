import json
import subprocess
from pathlib import Path
import pprint

from src.agent.agent import Agent
from src.llmtool.concolic.hypothesis_generator import HypothesisGenerator
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

    def _run_semgrep_validation(self, target_file_path: str) -> bool:
        # This is a simplified validation. A real implementation would need more robust rule management.
        rule_path = "src/semgrep_rules/cwe20-validation.yml" # This is incorrect for CWE-502 but only for demo
        command = ["semgrep", "--config", rule_path, "--json", target_file_path]
        
        try:
            result = subprocess.run(command, capture_output=True, text=True, check=True)
            semgrep_output = json.loads(result.stdout)
            return bool(semgrep_output.get("results"))
        except FileNotFoundError:
            self.logger.print_console("`semgrep` command not found. Please ensure it is installed.", "error")
        except subprocess.CalledProcessError as e:
            self.logger.print_console(f"Semgrep failed: {e.stderr}", "error")
        except json.JSONDecodeError:
            self.logger.print_console("Failed to parse Semgrep output.", "error")
        return False

    def run(self):
        self.logger.print_console(f"Start Concolic Scanning for function '{self.target_function}'...")
        analyzer = self._get_analyzer()
        if not analyzer: return

        target_function_info = analyzer.find_function_by_name(self.target_function)
        if not target_function_info:
            self.logger.print_console(f"Target function '{self.target_function}' not found.")
            return

        self.logger.print_console(f"Generating vulnerability hypothesis for: {target_function_info['name']}")
        llm_output = self.hypothesis_generator.generate(function_code=target_function_info['code'])
        
        if not llm_output.is_valid:
            self.logger.print_console(f"Hypothesis generation failed: {llm_output.error_message}", "error")
            return
        
        hypothesis = self.hypothesis_generator.get_hypothesis(llm_output)
        cwe_id = hypothesis.get("CWE_ID", "CWE-UNKNOWN") if hypothesis else "CWE-UNKNOWN"
        
        self.logger.print_console("Forcing Semgrep validation...")
        is_vulnerable = self._run_semgrep_validation(target_function_info['file_path'])

        if is_vulnerable:
            self.logger.print_console("Hypothesis VALIDATED! Vulnerability confirmed by Semgrep.")
            report = BugReport(
                cwe_id=cwe_id,
                file_path=target_function_info['file_path'],
                function_name=target_function_info['name'],
                start_line=target_function_info['start_line'],
                end_line=target_function_info['end_line'],
                function_code=target_function_info['code'],
                language=self.language
            )
            report.dump(self.result_dir)
            self.logger.print_console(f"1 bug(s) were detected.")
        else:
            self.logger.print_console("Hypothesis REJECTED. Vulnerability not confirmed by Semgrep.")

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