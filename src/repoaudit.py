import argparse
import glob
import sys
from agent.metascan import *
from agent.dfbscan import *

from tstool.analyzer.TS_analyzer import *
from tstool.analyzer.Cpp_TS_analyzer import *
from tstool.analyzer.Go_TS_analyzer import *
from tstool.analyzer.Java_TS_analyzer import *
from tstool.analyzer.Python_TS_analyzer import *

from typing import List

default_dfbscan_checkers = {
    "Cpp": ["MLK", "NPD", "UAF"],
    "Java": ["NPD"],
    "Python": ["NPD"],
    "Go": ["NPD"],
}


class RepoAudit:
    def __init__(
        self,
        args: argparse.Namespace,
    ):
        """
        Initialize BatchScan object with project details.
        """
        # argument format check
        self.args = args
        is_input_valid, error_messages = self.validate_inputs()

        if not is_input_valid:
            print("\n".join(error_messages))
            exit(1)

        self.project_path = args.project_path
        self.language = args.language
        self.code_in_files = {}

        self.model_name = args.model_name
        self.temperature = args.temperature
        self.call_depth = args.call_depth
        self.max_symbolic_workers = args.max_symbolic_workers
        self.max_neural_workers = args.max_neural_workers

        self.bug_type = args.bug_type
        self.is_reachable = args.is_reachable

        suffixs = []
        if self.language == "Cpp":
            suffixs = ["cpp", "cc", "hpp", "c", "h"]
        elif self.language == "Go":
            suffixs = ["go"]
        elif self.language == "Java":
            suffixs = ["java"]
        elif self.language == "Python":
            suffixs = ["py"]
        else:
            raise ValueError("Invalid language setting")

        # Load all files with the specified suffix in the project path
        self.travese_files(self.project_path, suffixs)

        if self.language == "Cpp":
            self.ts_analyzer = Cpp_TSAnalyzer(
                self.code_in_files, self.language, self.max_symbolic_workers
            )
        elif self.language == "Go":
            self.ts_analyzer = Go_TSAnalyzer(
                self.code_in_files, self.language, self.max_symbolic_workers
            )
        elif self.language == "Java":
            self.ts_analyzer = Java_TSAnalyzer(
                self.code_in_files, self.language, self.max_symbolic_workers
            )
        elif self.language == "Python":
            self.ts_analyzer = Python_TSAnalyzer(
                self.code_in_files, self.language, self.max_symbolic_workers
            )
        return

    def start_repo_auditing(self) -> None:
        """
        Start the batch scan process.
        """
        if self.args.scan_type == "metascan":
            metascan_pipeline = MetaScanAgent(
                self.project_path,
                self.language,
                self.ts_analyzer,
                self.model_name,
                self.temperature,
            )
            metascan_pipeline.start_scan()

        if self.args.scan_type == "dfbscan":
            dfbscan_agent = DFBScanAgent(
                self.bug_type,
                self.is_reachable,
                self.project_path,
                self.language,
                self.ts_analyzer,
                self.model_name,
                self.temperature,
                self.call_depth,
                self.max_neural_workers,
            )
            dfbscan_agent.start_scan()
        return

    def travese_files(self, project_path: str, suffixs: List) -> None:
        """
        Traverse all files in the project path.
        """
        for suffix in suffixs:
            for file in glob.glob(f"{project_path}/**/*.{suffix}", recursive=True):
                try:
                    with open(file, "r") as c_file:
                        c_file_content = c_file.read()
                        self.code_in_files[file] = c_file_content
                except:
                    print(f"Error reading file {file}")
        return

    def validate_inputs(self) -> Tuple[bool, List[str]]:
        err_messages = []

        # For each scan type, check required parameters.
        if self.args.scan_type == "dfbscan":
            if not self.args.model_name:
                err_messages.append("Error: --model-name is required for dfbscan.")
            if not self.args.bug_type:
                err_messages.append("Error: --bug -type is required for dfbscan.")
            if self.args.bug_type not in default_dfbscan_checkers[self.args.language]:
                err_messages.append("Error: Invalid bug type provided.")
        elif self.args.scan_type == "metascan":
            return (True, [])
        else:
            err_messages.append("Error: Unknown scan type provided.")
        return (len(err_messages) == 0, err_messages)


def configure_args():
    parser = argparse.ArgumentParser(
        description="RepoAudit: Run metascan or dfbscan on a project."
    )
    parser.add_argument(
        "--scan-type",
        required=True,
        choices=["metascan", "dfbscan"],
        help="The type of scan to perform.",
    )
    # Common parameters of metascan and dfbscan
    parser.add_argument("--project-path", required=True, help="Project path")
    parser.add_argument("--language", required=True, help="Programming language")
    parser.add_argument(
        "--max-symbolic-workers",
        type=int,
        default=30,
        help="Max symbolic workers for parsing-based analysis",
    )

    # Common parameters for dfbscan
    parser.add_argument("--model-name", help="The name of LLMs")
    parser.add_argument(
        "--temperature", type=float, default=0.5, help="Temperature for inference"
    )
    parser.add_argument("--call-depth", type=int, default=3, help="Call depth setting")
    parser.add_argument(
        "--max-neural-workers",
        type=int,
        default=1,
        help="Max neural workers for prompting-based analysis",
    )
    parser.add_argument("--bug-type", help="Bug type for dfbscan)")
    parser.add_argument(
        "--is-reachable", action="store_true", help="Flag for bugscan reachability"
    )

    args = parser.parse_args()
    return args


def main() -> None:
    args = configure_args()
    repoaudit = RepoAudit(args)
    repoaudit.start_repo_auditing()
    return


if __name__ == "__main__":
    main()
