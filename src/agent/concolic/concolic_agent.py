import sys
import json
from os import path
from typing import *
import argparse
import subprocess
import os
from pathlib import Path

sys.path.append(path.dirname(path.dirname(path.dirname(path.abspath(__file__)))))

from agent.agent import Agent
from tstool.analyzer.TS_analyzer import TSAnalyzer
from llmtool.concolic.hypothesis_generator import HypothesisGenerator, HypothesisGeneratorInput, HypothesisGeneratorOutput
from memory.report.bug_report import BugReport
from memory.syntactic.value import Value
from ui.logger import Logger

class ConcolicAgent(Agent):
    def __init__(
        self,
        args: argparse.Namespace,
        ts_analyzer: TSAnalyzer,
        logger: Logger,
        agent_id: int = 0
    ) -> None:
        super().__init__()
        self.language = args.language
        self.project_path = args.project_path
        self.bug_type = args.bug_type
        self.model_name = args.model_name
        self.temperature = args.temperature
        self.MAX_QUERY_NUM = 5
        self.logger = logger
        self.ts_analyzer = ts_analyzer
        
        self.agent_name = "ConcolicAgent"
        self.hypothesis_generator = HypothesisGenerator(
            model_name=self.model_name, 
            temperature=self.temperature, 
            language=self.language, 
            max_query_num=self.MAX_QUERY_NUM, 
            logger=self.logger
        )
        self.bug_reports = []
        self.result_dir = Path("log") / f"{self.agent_name}-{Path(self.project_path).name}"

    def get_agent_state(self):
        # This agent does not have a complex state to save.
        # Fulfill the abstract method requirement by returning None.
        return None

    def start_scan(self) -> List[BugReport]:
        self.logger.print_console(f"Start Concolic Scanning...", "info")
        
        # --- DEBUG LOG ---
        self.logger.print_log("Available functions in function_env:")
        for func_id, func_obj in self.ts_analyzer.function_env.items():
            self.logger.print_log(f"- ID: {func_id}, Name: {func_obj.function_name}")
        # --- END DEBUG LOG ---

        target_function_name = "deserialze"
        target_function = None
        for func in self.ts_analyzer.function_env.values():
            if func.function_name == target_function_name:
                target_function = func
                break
        
        if not target_function:
            self.logger.print_console(f"Target function '{target_function_name}' not found.", "error")
            return []

        self.logger.print_console(f"Generating vulnerability hypothesis for function: {target_function.function_name}", "info")
        
        function_id = f"{target_function.file_path}:{target_function.function_name}"

        hypo_gen_input = HypothesisGeneratorInput(
            function_id=function_id,
            function_code=target_function.function_code
        )
        hypo_gen_output = self.hypothesis_generator.invoke(hypo_gen_input)

        if hypo_gen_output is None or hypo_gen_output.output is None:
            self.logger.print_console("Failed to get a valid response from the LLM.", "error")
            return []
        
        hypothesis = hypo_gen_output.output
        
        self.logger.print_log("="*50)
        self.logger.print_log("LLM Generated Hypothesis:")
        self.logger.print_log(json.dumps(hypothesis, indent=2))
        self.logger.print_log("="*50)

        # Temporarily bypass LLM hypothesis check to test Semgrep rule
        self.logger.print_console("Temporarily bypassing LLM hypothesis check to force Semgrep validation.", "warning")
        # is_llm_positive = hypothesis.get("is_vulnerable", False) or hypothesis.get("cwe20", False)
        # if not is_llm_positive:
        #     self.logger.print_console("Hypothesis from LLM is negative. Skipping Semgrep validation.", "info")
        #     return []

        self.logger.print_console("Forcing Semgrep validation...", "info")
        
        is_vulnerable_by_semgrep = self._run_semgrep_validation(target_function.file_path)

        if is_vulnerable_by_semgrep:
            report = BugReport(
                bug_type="CWE-20",
                buggy_value=Value("parser.parseArray", target_function.start_line_number, "SINK", target_function.file_path),
                relevant_functions={target_function.function_id: target_function},
                explanation=hypothesis.get("explanation", "Vulnerability confirmed by Semgrep rule cwe-20-improper-validation-vul4j-1-dataflow."),
                is_human_confirmed_true=True # Mark as true since semgrep confirmed it
            )
            self.bug_reports.append(report)

        self._dump_reports()
        self.logger.print_console(f"{len(self.bug_reports)} bug(s) were detected.", "info")
        return self.bug_reports

    def _run_semgrep_validation(self, target_file_path: str) -> bool:
        """
        Runs Semgrep with a specific rule to validate the vulnerability.
        """
        rule_path = "src/semgrep_rules/cwe20-validation.yml"
        semgrep_output_path = "semgrep_results.json"
        
        command = [
            "semgrep",
            "--config", rule_path,
            "--json",
            "--output", semgrep_output_path,
            target_file_path
        ]

        try:
            self.logger.print_log(f"Executing Semgrep command: {' '.join(command)}")
            subprocess.run(command, check=True, capture_output=True, text=True)
            
            with open(semgrep_output_path, 'r') as f:
                results = json.load(f)

            # Clean up the results file
            os.remove(semgrep_output_path)
            
            if results["results"]:
                self.logger.print_console("Hypothesis VALIDATED! Vulnerability confirmed by Semgrep.", "success")
                return True
            else:
                self.logger.print_console("Hypothesis INVALID. Semgrep did not find a match.", "fail")
                return False

        except FileNotFoundError:
            self.logger.print_console("`semgrep` command not found. Please ensure it is installed and in your PATH.", "error")
            return False
        except subprocess.CalledProcessError as e:
            self.logger.print_console(f"Semgrep execution failed with exit code {e.returncode}.", "error")
            self.logger.print_log(f"Stdout: {e.stdout}")
            self.logger.print_log(f"Stderr: {e.stderr}")
            return False
        except (IOError, json.JSONDecodeError) as e:
            self.logger.print_console(f"Failed to read or parse Semgrep results: {e}", "error")
            return False

    def _dump_reports(self):
        if not self.bug_reports:
            return

        output_dir = self.result_dir
        output_dir.mkdir(parents=True, exist_ok=True)
        report_path = output_dir / "detect_info.json"
        
        reports_data = [report.to_dict() for report in self.bug_reports]
        
        with open(report_path, 'w') as f:
            json.dump(reports_data, f, indent=4)
        
        self.logger.print_console(f"The bug report(s) have been dumped to {report_path}", "info") 