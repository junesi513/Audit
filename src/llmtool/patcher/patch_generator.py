from src.llmtool.LLM_utils import Prompt, LLMResponse
from src.memory.semantic.state import State
import json

class PatchGenerator:
    def __init__(self, **kwargs):
        self.prompt = Prompt(**kwargs)
        self.tool_name = "PatchGenerator"

    def run(self, **kwargs) -> LLMResponse:
        """
        Runs the PatchGenerator tool to generate a patch for a vulnerability.

        Args:
            bug_report (dict): The bug report containing details about the vulnerability.
            func_code (str): The source code of the vulnerable function.

        Returns:
            LLMResponse: The response from the LLM, containing the patched code.
        """
        bug_report: dict = kwargs['bug_report']
        func_code: str = kwargs['func_code']

        bug_report_str = json.dumps(bug_report, indent=4)

        user_prompt = self.prompt.get_user_prompt(
            func_code=func_code,
            bug_report=bug_report_str
        )

        response = self.prompt.run(user_prompt)
        return response 