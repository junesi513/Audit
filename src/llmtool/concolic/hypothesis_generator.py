import sys
import json
from os import path
from pathlib import Path
import re
from dataclasses import dataclass

sys.path.append(path.dirname(path.dirname(path.dirname(path.abspath(__file__)))))

from src.llmtool.LLM_utils import LLM, Prompt, LLMToolOutput, LLMToolInput

@dataclass
class HypothesisGeneratorInput(LLMToolInput):
    function_id: str  # Use a simple ID for hashing
    function_code: str

    def __hash__(self):
        return hash(self.function_id)

    def __eq__(self, other):
        return isinstance(other, HypothesisGeneratorInput) and self.function_id == other.function_id

@dataclass
class HypothesisGeneratorOutput(LLMToolOutput):
    output: dict
    error: str = None

class HypothesisGenerator:
    def __init__(self, model_name: str, language: str, api_key: str = None, **kwargs):
        self.language = language
        self.prompt_path = self._get_default_prompt_path()
        self.prompt = Prompt(self.prompt_path)
        self.model = LLM(model_name=model_name, api_key=api_key)

    def _get_default_prompt_path(self):
        base_path = Path(__file__).resolve().parents[3]
        return f"{base_path}/src/prompt/{self.language.capitalize()}/concolic/hypothesis_generator.json"

    def generate(self, function_code: str) -> LLMToolOutput:
        prompt_str = self.prompt.get_string_with_inputs({'FUNC_CODE': function_code})
        raw_output = self.model.generate(prompt_str)
        return self._post_process(raw_output)

    def _post_process(self, output: str) -> LLMToolOutput:
        try:
            # The JSON content is assumed to be within ```json ... ```
            json_match = re.search(r"```json\n(.*?)\n```", output, re.DOTALL)
            if json_match:
                json_str = json_match.group(1)
                parsed_json = json.loads(json_str)
                return LLMToolOutput(is_valid=True, output=parsed_json)
        except json.JSONDecodeError as e:
            return LLMToolOutput(is_valid=False, error_message=f"JSONDecodeError: {e}")
        except Exception as e:
            return LLMToolOutput(is_valid=False, error_message=f"An unexpected error occurred: {e}")
        
        return LLMToolOutput(is_valid=False, error_message="Could not extract JSON from LLM output.")

    def get_hypothesis(self, output: LLMToolOutput):
        return output.output if output.is_valid else None