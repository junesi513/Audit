import sys
import json
from os import path
sys.path.append(path.dirname(path.dirname(path.dirname(path.abspath(__file__)))))

from src.llmtool.LLM_tool import *
from src.llmtool.LLM_utils import *

BASE_PATH = path.dirname(path.dirname(path.dirname(path.dirname(path.abspath(__file__)))))

class StepTracer(LLMTool):
    def __init__(
        self,
        model_name: str,
        temperature: float,
        language: str,
        max_query_num: int,
        logger: Logger,
    ) -> None:
        super().__init__(model_name, temperature, language, max_query_num, logger)
        # Load prompt from json file directly
        prompt_path = f"{BASE_PATH}/src/prompt/{language.capitalize()}/dfbscan/step_tracer.json"
        with open(prompt_path, 'r') as f:
            prompt_data = json.load(f)
        self.prompt_template = prompt_data["question_template"]

    def _get_prompt(self, input: StepTracerInput) -> str:
        """
        Formats the prompt with the source variable and code snippet.
        """
        return self.prompt_template.format(
            SRC_NAME=input.variable.name,
            CODE_SNIPPET=input.code_snippet,
        )

    def _parse_response(self, response: str) -> StepTracerOutput:
        """
        Parses the LLM's response to extract the next variable name.
        """
        if response is None:
            return None
        # The response is expected to be just the variable name, clean it up.
        next_variable_name = response.strip().splitlines()[0]
        return StepTracerOutput(next_variable_name=next_variable_name)

    def invoke(self, input: StepTracerInput) -> StepTracerOutput:
        """
        Invokes the LLM tool to trace one step of data flow.
        """
        prompt = self._get_prompt(input)
        response = self.llm_util.ask_llm(prompt, self.model_name, self.temperature)
        return self._parse_response(response) 