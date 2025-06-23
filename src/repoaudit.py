import argparse
import os
import sys
from pathlib import Path

from src.agent.concolic.concolic_agent import ConcolicAgent
from src.agent.dfbscan import DFBScanAgent
from src.agent.metascan import MetaScanAgent
from src.agent.patcher.patcher_agent import PatcherAgent
from src.ui.logger import Logger


def main():
    parser = argparse.ArgumentParser(description='RepoAudit tool for vulnerability detection.')
    parser.add_argument('--project_path', type=str, required=True, help='Path to the project to be audited.')
    parser.add_argument('--scan_type', type=str, choices=['metascan', 'dfbscan', 'concolic', 'patch'], required=True, help='Type of scan to perform.')
    parser.add_argument('--model_name', type=str, default='gemini-1.5-pro-latest', help='Name of the model to use.')
    parser.add_argument('--language', type=str, required=True, help='Language of the project (e.g., Java, Cpp).')
    parser.add_argument('--tag', type=str, help='A tag for the audit session.')
    parser.add_argument('--api_key', type=str, default=os.getenv("GOOGLE_API_KEY"), help='API key for the LLM.')
    parser.add_argument('--prompt_path', type=str, default='src/prompt', help='Base path to the prompt directory.')
    parser.add_argument('--log_dir', type=str, default='log', help='Directory to save logs.')

    # Concolic-specific arguments
    parser.add_argument('--target_function', type=str, help='The target function to be analyzed by the concolic agent.')
    parser.add_argument('--cwe_id', type=str, help='The CWE ID of the vulnerability to be analyzed.')
    parser.add_argument('--semgrep_rule_path', type=str, default='src/semgrep_rules', help='Path to the Semgrep rules directory.')

    # Patcher-specific arguments
    parser.add_argument('--input_dir', type=str, help='Input directory containing the detection report (detect_info.json).')


    args = parser.parse_args()

    # Setup Logger
    project_name = Path(args.project_path).name
    log_dir = Path(args.log_dir)
    log_dir.mkdir(exist_ok=True)
    
    # Use tag for log file name if provided
    log_file_name_parts = [args.scan_type, project_name]
    if args.tag:
        log_file_name_parts.append(args.tag)
    log_file_path = log_dir / f"{'-'.join(log_file_name_parts)}.log"

    logger = Logger(str(log_file_path))

    # Prepare arguments for agents
    agent_args = {
        'project_path': args.project_path,
        'language': args.language,
        'model_name': args.model_name,
        'api_key': args.api_key,
        'prompt_path': os.path.join(args.prompt_path, args.language),
        'logger': logger,
        'tag': args.tag,
        'result_dir': None, # This will be set within the agent
    }
    
    agent = None
    if args.scan_type == 'metascan':
        agent = MetaScanAgent(**agent_args)
    elif args.scan_type == 'concolic':
        agent_args['prompt_path'] = os.path.join(agent_args['prompt_path'], 'concolic', 'hypothesis_generator.json')
        agent_args['target_function'] = args.target_function
        agent_args['cwe_id'] = args.cwe_id
        agent_args['semgrep_rule_path'] = args.semgrep_rule_path
        agent = ConcolicAgent(**agent_args)
    elif args.scan_type == 'patch':
        agent_args['prompt_path'] = os.path.join(agent_args['prompt_path'], 'patcher', 'patch_generator.json')
        agent_args['input_dir'] = args.input_dir
        agent = PatcherAgent(**agent_args)
    elif args.scan_type == 'dfbscan':
        # NOTE: DFBScanAgent seems to have a different constructor signature.
        # This part might need adjustment if dfbscan is to be used.
        logger.error("DFBScanAgent is not fully integrated in this script version.")
        # agent = DFBScanAgent(...) 
    else:
        logger.error(f"Unknown scan type: {args.scan_type}")
        sys.exit(1)

    if agent:
        try:
            agent.start_scan()
        except Exception as e:
            logger.print_console(f"An error occurred while running the agent: {e}")
            sys.exit(1)
    else:
        logger.print_console("Agent could not be initialized.")
        sys.exit(1)


if __name__ == '__main__':
    main()
