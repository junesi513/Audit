from pathlib import Path
import re

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
        if output:
            return LLMToolOutput(is_valid=True, output=output)
        else:
            return LLMToolOutput(is_valid=False, error_message="LLM returned an empty response.")

    def get_text(self, output: LLMToolOutput) -> str:
        return output.output if output.is_valid else "" 