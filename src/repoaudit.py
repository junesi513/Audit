import argparse
import glob
import sys
from agent.metascan import *
from agent.dfbscan import *
from agent.concolic.concolic_agent import ConcolicAgent

from tstool.analyzer.TS_analyzer import *
from tstool.analyzer.Cpp_TS_analyzer import *
from tstool.analyzer.Go_TS_analyzer import *
from tstool.analyzer.Java_TS_analyzer import *
from tstool.analyzer.Python_TS_analyzer import *

from typing import List, Tuple
from ui.logger import Logger
from pathlib import Path

default_dfbscan_checkers = {
    "Cpp": ["MLK", "NPD", "UAF"],
    "Java": ["NPD", "CWE-20"],
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

        # Use the log path from arguments if provided, otherwise create a default one.
        if args.log_path:
            self.log_file_path = Path(args.log_path)
        else:
            log_dir = Path("log")
            log_dir.mkdir(exist_ok=True)
            project_name = Path(self.project_path).name
            self.log_file_path = log_dir / f"{self.args.scan_type}-{project_name}.log"
        
        # Ensure the parent directory for the log file exists.
        self.log_file_path.parent.mkdir(parents=True, exist_ok=True)
        
        self.logger = Logger(str(self.log_file_path))

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

        self.ts_analyzer = self._get_ts_analyzer()
        return

    def start_repo_auditing(self) -> None:
        """
        Start the batch scan process.
        """
        self.logger.print_console(f"Start repo auditing...")
        
        # The TSAnalyzer automatically runs its analysis upon instantiation.
        # No further method calls are needed here.
        
        if self.args.scan_type == "metascan":
            metascan_pipeline = MetaScanAgent(
                self.project_path,
                self.language,
                self.ts_analyzer,
                self.model_name,
                self.temperature,
            )
            metascan_pipeline.start_scan()
        elif self.args.scan_type == "dfbscan":
            dfbscan_agent = DFBScanAgent(
                self.language,
                self.project_path,
                self.bug_type,
                self.model_name,
                self.ts_analyzer,
                self.is_reachable,
                0,
                5,
                1,
                0,
            )
            dfbscan_agent.start_scan()
        elif self.args.scan_type == "concolic":
            concolic_agent = ConcolicAgent(
                self.args,
                self.ts_analyzer,
                self.logger
            )
            concolic_agent.start_scan()
        return

    def travese_files(self, project_path: str, suffixs: List) -> None:
        """
        Traverse all files in the project path.
        """
        self.logger.print_log(f"Searching for files with suffixes {suffixs} in '{project_path}'")
        file_count = 0
        loaded_files = set()

        for suffix in suffixs:
            # Pattern 1: Files directly in the project_path
            pattern1 = f"{project_path}/*.{suffix}"
            # Pattern 2: Files in all subdirectories
            pattern2 = f"{project_path}/**/*.{suffix}"
            
            self.logger.print_log(f"Using glob patterns: '{pattern1}' and '{pattern2}'")
            
            found_files = glob.glob(pattern1) + glob.glob(pattern2, recursive=True)
            
            self.logger.print_log(f"Found files for suffix '{suffix}': {found_files}")
            
            for file in found_files:
                if file in loaded_files:
                    continue
                try:
                    with open(file, "r") as c_file:
                        c_file_content = c_file.read()
                        self.code_in_files[file] = c_file_content
                        file_count += 1
                        loaded_files.add(file)
                        self.logger.print_log(f"Successfully loaded file: {file}")
                except Exception as e:
                    self.logger.print_log(f"Error reading file {file}: {e}")
        self.logger.print_log(f"Finished traversing. Total files loaded: {file_count}")
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
        elif self.args.scan_type == "concolic":
            return (True, [])
        else:
            err_messages.append("Error: Unknown scan type provided.")
        return (len(err_messages) == 0, err_messages)

    def _get_ts_analyzer(self):
        if self.language == "Cpp":
            return Cpp_TSAnalyzer(
                self.code_in_files, self.language, self.max_symbolic_workers
            )
        elif self.language == "Go":
            return Go_TSAnalyzer(
                self.code_in_files, self.language, self.max_symbolic_workers
            )
        elif self.language == "Java":
            return Java_TSAnalyzer(
                self.code_in_files, self.language, self.max_symbolic_workers
            )
        elif self.language == "Python":
            return Python_TSAnalyzer(
                self.code_in_files, self.language, self.max_symbolic_workers
            )
        else:
            raise ValueError("Invalid language setting")


def configure_args():
    parser = argparse.ArgumentParser(
        description="RepoAudit: Run metascan or dfbscan on a project."
    )
    parser.add_argument(
        "--scan-type",
        required=True,
        choices=["metascan", "dfbscan", "concolic"],
        help="Scan type",
    )
    # Common parameters of metascan and dfbscan
    parser.add_argument(
        "--project-path",
        default=".",
        help="The project path to be analyzed. Defaults to the current directory.",
    )
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

    # Add arguments for concolic scan
    parser.add_argument("--target-file", help="The target file path for concolic testing.")
    parser.add_argument("--function-name", help="The target function name for concolic testing.")

    # Add missing arguments
    parser.add_argument("--ts-lib-path", help="Path to the tree-sitter library build file.")
    parser.add_argument("--log-path", help="Path to the log file.")

    args = parser.parse_args()
    return args


def main() -> None:
    args = configure_args()
    repoaudit = RepoAudit(args)
    repoaudit.start_repo_auditing()
    return


if __name__ == "__main__":
    main()
