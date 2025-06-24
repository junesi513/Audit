import sys
import json
from os import path
from pathlib import Path

sys.path.append(path.dirname(path.dirname(path.dirname(path.abspath(__file__)))))

from src.llmtool.LLM_tool import *

BASE_PATH = Path(__file__).resolve().parents[3]

class IntraDataFlowAnalyzer(LLMTool):
    def __init__(
        self,
        model_name: str,
        temperature: float,
        language: str,
        max_query_num: int,
        logger: Logger,
        bug_type: str,
    ) -> None:
        super().__init__(model_name, temperature, language, max_query_num, logger)
        
        self.bug_type = bug_type
        prompt_file_name = "CWE20_patch_comparison" if self.bug_type == "CWE-20" else "intra_dataflow_analyzer"
        prompt_path = f"{BASE_PATH}/src/prompt/{language.capitalize()}/dfbscan/{prompt_file_name}.json"
        with open(prompt_path, 'r') as f:
            self.prompt_template_data = json.load(f)
        self.prompt_template = self.prompt_template_data["question_template"]

    def _get_prompt(self, input: IntraDataFlowAnalyzerInput) -> str:
        if self.bug_type == "CWE-20":
            return self.prompt_template.format(
                FUNC_CODE=input.function.source_code,
            )

        sinks_str = "\\n".join([f"- {s[0]} at line {s[1]}" for s in input.sink_values])
        local_vars_str = "\\n".join([f"- {var}" for var in input.local_vars])
        assignments_str = "\\n".join([f"- {assign}" for assign in input.assignments])

        return self.prompt_template.format(
            FUNC_CODE=input.function.source_code,
            SRC_NAME=input.src_value.name,
            SINKS_STR=sinks_str,
            LOCAL_VARS=local_vars_str,
            ASSIGNMENTS=assignments_str,
        )

    def _parse_response(self, response: str, input: LLMToolInput = None) -> IntraDataFlowAnalyzerOutput:
        if self.bug_type == "CWE-20":
            if "type erasure" in response.lower() and "semantic contract" in response.lower() and "precision loss" in response.lower():
                vuln_path = [Value("VULNERABILITY_CONFIRMED", 0, ValueLabel.SINK, "")]
                return IntraDataFlowAnalyzerOutput(reachable_values=[vuln_path])
            else:
                return IntraDataFlowAnalyzerOutput(reachable_values=[])

        paths = []
        try:
            path_str = response.strip()
            if "Path:" in path_str:
                path_str = path_str.split("Path:")[1].strip()
            
            var_names = [v.strip() for v in path_str.split("->")]
            path_values = [Value(name, 0, ValueLabel.VAR, "") for name in var_names]
            paths.append(path_values)
        except Exception:
            pass

        return IntraDataFlowAnalyzerOutput(reachable_values=paths)
