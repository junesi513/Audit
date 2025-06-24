from pathlib import Path
import re
import json
from typing import List

from src.llmtool.LLM_utils import LLM, Prompt, LLMToolOutput

class PatchGenerator:
    def __init__(self, model_name: str, language: str, api_key: str = None, **kwargs):
        self.language = language
        self.prompt_path = self._get_default_prompt_path()
        self.prompt = Prompt(self.prompt_path)
        self.model = LLM(model_name=model_name, api_key=api_key)

    def _get_default_prompt_path(self):
        base_path = Path(__file__).resolve().parents[3]
        return f"{base_path}/src/prompt/{self.language.capitalize()}/patcher/patch_generator.json"

    def generate(self, function_code: str, bug_report: str) -> LLMToolOutput:
        prompt_str = self.prompt.get_string_with_inputs({
            'FUNC_CODE': function_code,
            'BUG_REPORT': bug_report
        })
        raw_output = self.model.generate(prompt_str)
        return self._post_process(raw_output)

    def _post_process(self, output: str) -> LLMToolOutput:
        try:
            # Clean up the output to extract only the JSON part
            json_match = re.search(r'```json\n({.*?})\n```', output, re.DOTALL)
            if json_match:
                json_str = json_match.group(1)
            else:
                # If no markdown block, assume the whole output is the json
                json_str = output

            data = json.loads(json_str)
            patches = data.get("patches")

            if not patches or not isinstance(patches, list):
                return LLMToolOutput(is_valid=False, error_message="LLM response did not contain a valid 'patches' list.")

            return LLMToolOutput(is_valid=True, output=patches)
        except json.JSONDecodeError as e:
            return LLMToolOutput(is_valid=False, error_message=f"Failed to decode LLM response as JSON: {e}")
        except Exception as e:
            return LLMToolOutput(is_valid=False, error_message=f"An unexpected error occurred during post-processing: {e}")

    def get_text(self, output: LLMToolOutput) -> str:
        # This method is less relevant now, but can return the first patch for compatibility
        if output.is_valid and output.output:
            return output.output[0]
        return "" 