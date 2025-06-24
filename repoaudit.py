import argparse
import os
from src.agent.concolic.concolic_agent import ConcolicAgent
from src.agent.patcher.patcher_agent import PatcherAgent
from src.ui.logger import Logger

def main():
    parser = argparse.ArgumentParser(description="RepoAudit main script")
    parser.add_argument("--scan_type", required=True, choices=['concolic', 'patch'], help="Type of scan to perform")
    parser.add_argument("--project_path", required=True, help="Path to the project to be scanned")
    parser.add_argument("--language", required=True, help="Language of the project")
    parser.add_argument("--target_function", help="Target function for concolic scanning")
    parser.add_argument("--input_dir", help="Input directory for patcher agent")
    parser.add_argument("--tag", default="default", help="A tag for the run")
    parser.add_argument("--model_name", default="gemini-1.5-pro-latest", help="LLM model name")
    parser.add_argument("--api_key", default=os.getenv("GOOGLE_API_KEY"), help="Google API key")
    
    args = parser.parse_args()

    agent_kwargs = {
        'project_path': args.project_path,
        'language': args.language,
        'tag': args.tag,
        'model_name': args.model_name,
        'api_key': args.api_key
    }

    if args.scan_type == 'concolic':
        agent_kwargs['target_function'] = args.target_function
        agent = ConcolicAgent(**agent_kwargs)
    elif args.scan_type == 'patch':
        agent_kwargs['input_dir'] = args.input_dir
        agent = PatcherAgent(**agent_kwargs)
    else:
        print(f"Unknown scan type: {args.scan_type}")
        return

    agent.run()

if __name__ == "__main__":
    main()
