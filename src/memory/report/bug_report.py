import json
from pathlib import Path


class BugReport:
    def __init__(
        self,
        cwe_id: str,
        file_path: str,
        function_name: str,
        start_line: int,
        end_line: int,
        function_code: str,
        language: str,
        explanation: str = "N/A",
        details: dict = None,
    ) -> None:
        """
        :param cwe_id: the CWE ID
        :param file_path: the file path
        :param function_name: the function name
        :param start_line: the start line
        :param end_line: the end line
        :param function_code: the function code
        :param language: the language
        :param explanation: the explanation
        :param details: A dictionary containing detailed information about the vulnerability (e.g., source, sink)
        """
        self.cwe_id = cwe_id
        self.file_path = file_path
        self.function_name = function_name
        self.start_line = start_line
        self.end_line = end_line
        self.function_code = function_code
        self.language = language
        self.explanation = explanation
        self.details = details or {}

    def to_dict(self) -> dict:
        return {
            "cwe_id": self.cwe_id,
            "file_path": self.file_path,
            "function_name": self.function_name,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "function_code": self.function_code,
            "language": self.language,
            "explanation": self.explanation,
            "details": self.details,
        }

    def dump(self, output_dir: Path, filename: str = "bug_report.json"):
        report_path = output_dir / filename
        with report_path.open('w') as f:
            json.dump(self.to_dict(), f, indent=4)

    def __str__(self):
        return json.dumps(self.to_dict(), indent=4)
