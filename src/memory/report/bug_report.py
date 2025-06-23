from memory.syntactic.function import *
from memory.syntactic.value import *
from typing import Dict


class BugReport:
    def __init__(
        self,
        bug_type: str,
        buggy_value: Value,
        relevant_functions: Dict[int, Function],
        explanation: str,
        is_human_confirmed_true: bool = None,
    ) -> None:
        """
        :param bug_type: the bug type
        :param buggy_value: the buggy value
        :param relevant_functions: the relevant functions
        :param explanation: the explanation
        """
        self.bug_type = bug_type
        self.buggy_value = buggy_value
        self.relevant_functions = relevant_functions
        self.explanation = explanation
        self.is_human_confirmed_true = is_human_confirmed_true
        return

    def to_dict(self) -> dict:
        # Assuming there is at least one relevant function, which should be the case.
        first_func_id = next(iter(self.relevant_functions))
        first_func = self.relevant_functions[first_func_id]

        return {
            "bug_type": self.bug_type,
            "file_path": first_func.file_path,
            "function_name": first_func.function_name,
            "function_code": first_func.function_code,
            "start_line": first_func.start_line_number,
            "end_line": first_func.end_line_number,
            "buggy_value": str(self.buggy_value),
            "explanation": self.explanation,
            "is_human_confirmed_true": (
                str(self.is_human_confirmed_true)
                if self.is_human_confirmed_true is not None
                else "unknown"
            ),
        }

    def __str__(self):
        return str(self.to_dict())
