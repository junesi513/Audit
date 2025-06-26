import argparse
import os
import json
import glob
from src.agent.concolic.concolic_agent import ConcolicAgent
# from src.agent.dfbscan import DFBScanAgent
from src.agent.patcher.patcher_agent import PatcherAgent
from src.memory.semantic.dfbscan_state import DFBScanState
from src.tstool.analyzer import (
    TSAnalyzer,
    JavaTSAnalyzer,
)
from src.ui.logger import Logger
import logging

# def get_code_in_files(project_path: str, language: str) -> dict:
#     code_in_files = {}
#     extensions = {
#         'cpp': ['*.cpp', '*.h', '*.cc', '*.hpp'],
#         'go': ['*.go'],
#         'java': ['*.java'],
#         'python': ['*.py']
#     }
#     for ext in extensions.get(language.lower(), []):
#         for file_path in glob.glob(os.path.join(project_path, '**', ext), recursive=True):
#             with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
#                 code_in_files[file_path] = f.read()
#     return code_in_files

def main():
    parser = argparse.ArgumentParser(description="RepoAudit: An AI-powered Static Analyzer")
    parser.add_argument('--project-path', type=str, required=True, help="Path to the code repository, or a single file for concolic scan.")
    parser.add_argument('--language', type=str, required=True, help="Programming language of the repository.")
    parser.add_argument("--scan-type", required=True, choices=['concolic', 'patch', 'dfbscan'], help="Type of scan to perform")
    parser.add_argument("--target-function", help="Target function for concolic scanning. If not provided, all functions will be scanned.")
    parser.add_argument("--input-dir", help="Input directory for patcher agent")
    parser.add_argument("--bug-type", help="Bug type for dfbscan")
    parser.add_argument("--is-reachable", action='store_true', help="Enable reachability analysis for dfbscan")
    parser.add_argument("--call-depth", type=int, default=5, help="Call depth for dfbscan")
    parser.add_argument("--max-neural-workers", type=int, default=30, help="Max neural workers for dfbscan")
    parser.add_argument("--tag", default="default", help="A tag for the run")
    parser.add_argument("--model-name", type=str, default="gemini-1.5-pro-latest", help="Name of the model to use.")
    parser.add_argument("--temperature", type=float, default=0.0, help="Temperature for LLM")
    parser.add_argument("--api-key", required=True, help="Google API key")
    
    args = parser.parse_args()

    # Setup logger
    log_file_path = f"log/{args.tag}.log"
    os.makedirs("log", exist_ok=True)
    logger = Logger(args.tag, log_file=log_file_path, log_level=logging.DEBUG)

    agent_kwargs = {
        'project_path': args.project_path,
        'language': args.language,
        'tag': args.tag,
        'model_name': args.model_name,
        'api_key': args.api_key,
        'logger': logger,
    }

    if args.scan_type == 'concolic':
        agent = ConcolicAgent(agent_kwargs)
        
        target_file = args.project_path
        if not os.path.isfile(target_file):
            logger.print_console(f"Error: For concolic scan, --project-path must be a file. Path given: '{target_file}'", "error")
            return
            
        # Create a minimal state object to pass the file path
        state = DFBScanState(
            target_path=target_file,
            bug_type=args.bug_type or "CWE20"
        )
        agent.run_agent(state)
    elif args.scan_type == 'patch':
        agent_kwargs['input_dir'] = args.input_dir
        agent = PatcherAgent(**agent_kwargs)
        agent.run()
    elif args.scan_type == 'dfbscan':
        logger.print_console("dfbscan is currently disabled.", "warning")
        return
    else:
        print(f"Unknown scan type: {args.scan_type}")
        return

    # logger.print_console("RepoAudit finished.", "info")
    # logger.close()

if __name__ == '__main__':
    main()
