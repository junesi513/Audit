import sys
import json
from os import path
from pathlib import Path

sys.path.append(path.dirname(path.dirname(path.dirname(path.abspath(__file__)))))

from src.llmtool.LLM_tool import *

BASE_PATH = Path(__file__).resolve().parent.parent.parent

class IntraDataFlowAnalyzer(LLMTool):
    def _get_default_prompt_path(self) -> str:
        prompt_file_name = "CWE20_patch_comparison" if self.bug_type == "CWE-20" else "intra_dataflow_analyzer"
        return f"{BASE_PATH}/prompt/{self.language.capitalize()}/dfbscan/{prompt_file_name}.json"

    def __init__(
        self,
        model_name: str,
        language: str,
        bug_type: str,
        **kwargs,
    ) -> None:
        self.bug_type = bug_type
        super().__init__(model_name, language, **kwargs)

    def _get_prompt(self, input: IntraDataFlowAnalyzerInput) -> str:
        prompt_template = self.prompt.get("question_template")
        if self.bug_type == "CWE-20":
            return prompt_template.format(
                FUNC_CODE=input.function.source_code,
            )

        sinks_str = "\\n".join([f"- {s[0]} at line {s[1]}" for s in input.sink_values])
        local_vars_str = "\\n".join([f"- {var}" for var in input.local_vars])
        assignments_str = "\\n".join([f"- {assign}" for assign in input.assignments])

        return prompt_template.format(
            FUNC_CODE=input.function.source_code,
            SRC_NAME=input.src_value.name,
            SINKS_STR=sinks_str,
            LOCAL_VARS=local_vars_str,
            ASSIGNMENTS=assignments_str,
        )

    def _parse_response(self, response: str, input: LLMToolInput = None) -> LLMToolOutput:
        # Implement parsing logic based on the expected response format
        # This is a placeholder and needs to be adapted
        try:
            parsed_data = json.loads(response)
            return IntraDataFlowAnalyzerOutput(reachable_values=parsed_data.get("reachable_values", []))
        except json.JSONDecodeError:
            # Handle cases where the response is not valid JSON
            return IntraDataFlowAnalyzerOutput(reachable_values=[])
