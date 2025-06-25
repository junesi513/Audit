from os import path
import json
import time
from typing import List, Set, Optional, Dict
from src.llmtool.LLM_utils import *
from src.llmtool.LLM_tool import *
from src.memory.syntactic.function import *
from src.memory.syntactic.value import *
from src.memory.syntactic.api import *

BASE_PATH = Path(__file__).resolve().parent.parent.parent


class PathValidatorInput(LLMToolInput):
    def __init__(
        self,
        bug_type: str,
        values: List[Value],
        values_to_functions: Dict[Value, Function],
    ) -> None:
        self.bug_type = bug_type
        self.values = values
        self.values_to_functions = values_to_functions
        return

    def __hash__(self) -> int:
        return hash(str([str(value) for value in self.values]))


class PathValidatorOutput(LLMToolOutput):
    def __init__(self, is_reachable: bool, explanation_str: str) -> None:
        self.is_reachable = is_reachable
        self.explanation_str = explanation_str
        return

    def __str__(self):
        return (
            f"Is reachable: {self.is_reachable} \\nExplanation: {self.explanation_str}"
        )


class PathValidator(LLMTool):
    def _get_default_prompt_path(self) -> str:
        return f"{BASE_PATH}/prompt/{self.language.capitalize()}/dfbscan/path_validator.json"

    def __init__(self, model_name: str, language: str, **kwargs) -> None:
        super().__init__(model_name, language, **kwargs)

    def _get_prompt(self, input: PathValidatorInput) -> str:
        path_str = " -> ".join([f"{v.name}:{v.start_line}" for v in input.values])
        return self.prompt.get("question_template").format(
            BUG_TYPE=input.bug_type,
            PATH_STR=path_str,
            FUNCS_CODE="\\n".join([f.source_code for f in input.values_to_functions.values()])
        )

    def _parse_response(self, response: str, input: LLMToolInput = None) -> PathValidatorOutput:
        try:
            # Assuming the response is a JSON string like '{"is_reachable": true, "explanation": "..."}'
            data = json.loads(response)
            is_reachable = data.get("is_reachable", False)
            explanation = data.get("explanation", "")
            return PathValidatorOutput(is_reachable=is_reachable, explanation_str=explanation)
        except (json.JSONDecodeError, AttributeError):
            # Fallback for non-JSON or malformed responses
            is_reachable = "yes" in response.lower()
            return PathValidatorOutput(is_reachable=is_reachable, explanation_str=response)
