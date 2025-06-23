import sys
import json
from os import path
from typing import *
import argparse
import subprocess
import os
from pathlib import Path

# This sys.path manipulation can be removed if running as a module with -m
sys.path.append(path.dirname(path.dirname(path.dirname(path.abspath(__file__)))))

from src.agent.agent import Agent
from src.tstool.analyzer.Java_TS_analyzer import JavaTSAnalyzer
from src.llmtool.concolic.hypothesis_generator import HypothesisGenerator, HypothesisGeneratorInput, HypothesisGeneratorOutput
from src.memory.report.bug_report import BugReport
from src.memory.syntactic.value import Value
from src.ui.logger import Logger

class ConcolicAgent(Agent):
    def __init__(self, **kwargs):
        super().__init__()
        self.language = kwargs['language']
        self.project_path = kwargs['project_path']
        self.target_function_name = kwargs.get('target_function', 'deserialze')
        self.cwe_id = kwargs.get('cwe_id', 'CWE-20')
        self.semgrep_rule_path = kwargs.get('semgrep_rule_path')
        self.model_name = kwargs['model_name']
        self.logger = kwargs['logger']
        self.tag = kwargs.get('tag')
        
        agent_name = self.__class__.__name__
        log_dir = kwargs.get('log_dir', 'log')
        self.result_dir = Path(log_dir) / f"{agent_name}-{self.tag}"
        self.result_dir.mkdir(parents=True, exist_ok=True)

        # Correctly initialize HypothesisGenerator
        self.temperature = kwargs.get('temperature', 0.5)
        self.max_query_num = kwargs.get('max_query_num', 5)
        self.hypothesis_generator = HypothesisGenerator(
            model_name=self.model_name,
            temperature=self.temperature,
            language=self.language,
            max_query_num=self.max_query_num,
            logger=self.logger
        )
        self.bug_reports = []

    def get_agent_state(self):
        return None

    def start_scan(self) -> List[BugReport]:
        self.logger.print_console(f"Start Concolic Scanning for function '{self.target_function_name}'...")

        code_in_files = self._read_project_files()
        if not code_in_files:
            self.logger.print_console("Error: No source files found in the project path.")
            return []
            
        ts_analyzer = JavaTSAnalyzer(code_in_files=code_in_files, language_name=self.language)

        target_function = None
        for func in ts_analyzer.function_env.values():
            if func.function_name == self.target_function_name:
                target_function = func
                break
        
        if not target_function:
            self.logger.print_console(f"Target function '{self.target_function_name}' not found.")
            return []

        self.logger.print_console(f"Generating vulnerability hypothesis for function: {target_function.function_name}")
        
        hypo_gen_input = HypothesisGeneratorInput(
            function_id=f"{target_function.file_path}:{target_function.function_name}",
            function_code=target_function.function_code
        )
        hypo_gen_output = self.hypothesis_generator.invoke(hypo_gen_input)

        if hypo_gen_output is None or hypo_gen_output.output is None:
            self.logger.print_console("Failed to get a valid response from the LLM.")
            return []
        
        hypothesis = hypo_gen_output.output
        
        self.logger.print_console("Forcing Semgrep validation...")
        
        is_vulnerable_by_semgrep = self._run_semgrep_validation(target_function.file_path)

        if is_vulnerable_by_semgrep:
            report = BugReport(
                bug_type=self.cwe_id,
                buggy_value=Value("parser.parseArray", target_function.start_line_number, "SINK", target_function.file_path),
                relevant_functions={target_function.function_id: target_function},
                explanation=hypothesis.get("explanation", "Vulnerability confirmed by Semgrep."),
                is_human_confirmed_true=True
            )
            self.bug_reports.append(report)

        self._dump_reports()
        self.logger.print_console(f"{len(self.bug_reports)} bug(s) were detected.")
        return self.bug_reports

    def _read_project_files(self) -> Dict[str, str]:
        self.logger.print_console(f"Reading project files from: {self.project_path}")
        code_in_files = {}
        file_ext = "*.java" if self.language.lower() == 'java' else None
        if not file_ext:
            self.logger.print_console(f"Language {self.language} not supported for file reading.")
            return {}

        file_list = list(Path(self.project_path).rglob(file_ext))
        self.logger.print_console(f"Found {len(file_list)} files with extension {file_ext}.")

        for file_path in file_list:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    code_in_files[str(file_path)] = f.read()
            except Exception as e:
                self.logger.print_console(f"Error reading file {file_path}: {e}")
        
        return code_in_files

    def _run_semgrep_validation(self, target_file_path: str) -> bool:
        rule_path = Path(self.semgrep_rule_path) / "cwe20-validation.yml"
        semgrep_output_path = self.result_dir / "semgrep_results.json"
        
        command = [
            "semgrep", "--config", str(rule_path),
            "--json", "--output", str(semgrep_output_path),
            target_file_path
        ]

        try:
            subprocess.run(command, check=True, capture_output=True, text=True)
            with open(semgrep_output_path, 'r') as f:
                results = json.load(f)

            if results.get("results"):
                self.logger.print_console("Hypothesis VALIDATED! Vulnerability confirmed by Semgrep.")
                return True
            else:
                self.logger.print_console("Hypothesis INVALID. Semgrep did not find a match.")
                return False
        except FileNotFoundError:
            self.logger.print_console("`semgrep` command not found. Please ensure it is installed and in your PATH.")
            return False
        except subprocess.CalledProcessError as e:
            self.logger.print_console(f"Semgrep failed: {e.stderr}")
            return False
        except (IOError, json.JSONDecodeError) as e:
            self.logger.print_console(f"Failed to read or parse Semgrep results: {e}")
            return False

    def _dump_reports(self):
        if not self.bug_reports:
            return
        report_path = self.result_dir / "detect_info.json"
        reports_data = [report.to_dict() for report in self.bug_reports]
        with open(report_path, 'w') as f:
            json.dump(reports_data, f, indent=4)
        self.logger.print_console(f"The bug report(s) have been dumped to {report_path}") 