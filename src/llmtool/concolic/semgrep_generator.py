from pathlib import Path
import re
import json

from src.llmtool.LLM_utils import LLM, Prompt, LLMToolOutput


class SemgrepGenerator:
    def __init__(self, model_name: str, language: str, api_key: str = None, temperature: float = 0.0, **kwargs):
        self.language = language
        base_path = Path(__file__).resolve().parents[3]
        self.prompt_path = f"{base_path}/src/prompt/{self.language.capitalize()}/concolic/semgrep_generator.json"
        self.prompt = Prompt(self.prompt_path)
        self.model = LLM(model_name=model_name, api_key=api_key, temperature=temperature)

    def generate(self, function_code: str, vulnerability_hypothesis: str, previous_error: str = None) -> LLMToolOutput:
        inputs = {
            'FUNC_CODE': function_code,
            'VUL_HYPOTHESIS': vulnerability_hypothesis
        }
        if previous_error:
            inputs['PREVIOUS_ERROR'] = previous_error

        prompt_str = self.prompt.get_string_with_inputs(inputs)
        raw_output = self.model.generate(prompt_str)
        return self._post_process(raw_output)

    def _post_process(self, llm_response_content: str) -> LLMToolOutput:
        """Processes the raw LLM output string to extract the Semgrep rule components as JSON."""
        
        json_str = None
        # First, try to find a JSON block specifically marked with ```json
        json_match = re.search(r"```json\n(.*?)\n```", llm_response_content, re.DOTALL)
        if json_match:
            json_str = json_match.group(1).strip()
        else:
            json_str = llm_response_content.strip()

        try:
            parsed_json = json.loads(json_str)
            return LLMToolOutput(is_valid=True, output=parsed_json, raw_output=llm_response_content)
        except json.JSONDecodeError as e:
            return LLMToolOutput(is_valid=False, error_message=f"LLM produced invalid JSON: {e}. Raw content: {llm_response_content}", raw_output=llm_response_content)
        except Exception as e:
            return LLMToolOutput(is_valid=False, error_message=f"An unexpected error occurred during post-processing: {e}", raw_output=llm_response_content)
        
        return LLMToolOutput(is_valid=False, error_message="Could not extract JSON from LLM output.", raw_output=llm_response_content) 