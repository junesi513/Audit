import sys
import json
from os import path
from pathlib import Path
import re
from dataclasses import dataclass

sys.path.append(path.dirname(path.dirname(path.dirname(path.abspath(__file__)))))

from llmtool.LLM_tool import *
from memory.syntactic.function import Function

BASE_PATH = Path(__file__).resolve().parents[3]

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

class HypothesisGenerator(LLMTool):
    def __init__(
        self,
        model_name: str,
        temperature: float,
        language: str,
        max_query_num: int,
        logger: Logger
    ) -> None:
        prompt_path = f"{BASE_PATH}/src/prompt/{language.capitalize()}/concolic/hypothesis_generator.json"
        with open(prompt_path, 'r') as f:
            self.prompt_template_data = json.load(f)
        
        self.system_role = self.prompt_template_data.get("system_role", "")
        
        super().__init__(model_name, temperature, language, max_query_num, logger)
        
        self.prompt_template = self.prompt_template_data["question_template"]

    def _get_prompt(self, llm_tool_input: LLMToolInput) -> str:
        if not isinstance(llm_tool_input, HypothesisGeneratorInput):
            raise TypeError("Input must be of type HypothesisGeneratorInput")

        func_code = llm_tool_input.function_code
        return self.prompt_template.replace("<FUNC_CODE>", func_code)

    def _parse_response(self, response: str, input: LLMToolInput = None) -> LLMToolOutput:
        try:
            # The JSON content is assumed to be within ```json ... ```
            json_str = self._extract_json_from_response(response)
            if not json_str:
                self.logger.print_log("No JSON block found in the response.")
                return None
            output_data = json.loads(json_str)
            return HypothesisGeneratorOutput(output=output_data)
        except json.JSONDecodeError as e:
            self.logger.print_log(f"Error decoding extracted JSON: {e}")
            self.logger.print_log(f"Raw Response Body: {response}")
            return None
        except Exception as e:
            self.logger.print_log(f"An unexpected error occurred during parsing: {e}")
            return None

    def _extract_json_from_response(self, response: str) -> str:
        json_match = re.search(r"```json\n(.*?)\n```", response, re.DOTALL)
        if not json_match:
            self.logger.info("LLM response did not contain a JSON markdown block. Falling back to raw search.")
            json_match = re.search(r"{\s*\"hypothesis_description\":.*}", response, re.DOTALL)

        if json_match:
            json_str = json_match.group(1) if len(json_match.groups()) > 0 else json_match.group(0)
            return json_str
        else:
            self.logger.info(f"Could not find any JSON in the response.\nRaw Response:\n{response}")
            return None 