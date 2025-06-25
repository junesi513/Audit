import argparse
import os
import glob
from src.agent.concolic.concolic_agent import ConcolicAgent
from src.agent.patcher.patcher_agent import PatcherAgent
from src.agent.dfbscan import DFBScanAgent
from src.tstool.analyzer.Cpp_TS_analyzer import Cpp_TSAnalyzer
from src.tstool.analyzer.Go_TS_analyzer import Go_TSAnalyzer
from src.tstool.analyzer.Java_TS_analyzer import JavaTSAnalyzer
from src.tstool.analyzer.Python_TS_analyzer import Python_TSAnalyzer
from src.ui.logger import Logger

def get_code_in_files(project_path: str, language: str) -> dict:
    code_in_files = {}
    extensions = {
        'cpp': ['*.cpp', '*.h', '*.cc', '*.hpp'],
        'go': ['*.go'],
        'java': ['*.java'],
        'python': ['*.py']
    }
    for ext in extensions.get(language.lower(), []):
        for file_path in glob.glob(os.path.join(project_path, '**', ext), recursive=True):
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                code_in_files[file_path] = f.read()
    return code_in_files

def main():
    parser = argparse.ArgumentParser(description="RepoAudit main script")
    parser.add_argument("--scan-type", required=True, choices=['concolic', 'patch', 'dfbscan'], help="Type of scan to perform")
    parser.add_argument("--project-path", required=True, help="Path to the project to be scanned")
    parser.add_argument("--language", required=True, help="Language of the project")
    parser.add_argument("--target-function", help="Target function for concolic scanning. If not provided, all functions will be scanned.")
    parser.add_argument("--input-dir", help="Input directory for patcher agent")
    parser.add_argument("--bug-type", help="Bug type for dfbscan")
    parser.add_argument("--is-reachable", action='store_true', help="Enable reachability analysis for dfbscan")
    parser.add_argument("--call-depth", type=int, default=5, help="Call depth for dfbscan")
    parser.add_argument("--max-neural-workers", type=int, default=30, help="Max neural workers for dfbscan")
    parser.add_argument("--tag", default="default", help="A tag for the run")
    parser.add_argument("--model-name", default="gemini-1.5-pro-latest", help="LLM model name")
    parser.add_argument("--temperature", type=float, default=0.0, help="Temperature for LLM")
    parser.add_argument("--api-key", default=os.getenv("GOOGLE_API_KEY"), help="Google API key")
    
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
        agent.run()
    elif args.scan_type == 'patch':
        agent_kwargs['input_dir'] = args.input_dir
        agent = PatcherAgent(**agent_kwargs)
        agent.run()
    elif args.scan_type == 'dfbscan':
        code_in_files = get_code_in_files(args.project_path, args.language)
        ts_analyzer = None
        lang = args.language.lower()
        
        if lang == 'cpp':
            ts_analyzer = Cpp_TSAnalyzer(code_in_files, 'Cpp')
        elif lang == 'go':
            ts_analyzer = Go_TSAnalyzer(code_in_files, 'Go')
        elif lang == 'java':
            ts_analyzer = JavaTSAnalyzer(code_in_files, 'Java')
        elif lang == 'python':
            ts_analyzer = Python_TSAnalyzer(code_in_files, 'Python')
        
        if ts_analyzer:
            agent = DFBScanAgent(
                language=args.language,
                project_path=args.project_path,
                bug_type=args.bug_type,
                model_name=args.model_name,
                ts_analyzer=ts_analyzer,
                is_reachable=args.is_reachable,
                temperature=args.temperature,
                call_depth=args.call_depth,
                max_neural_workers=args.max_neural_workers
            )
            agent.run()
        else:
            print(f"Unsupported language for dfbscan: {args.language}")
            return
    else:
        print(f"Unknown scan type: {args.scan_type}")
        return


if __name__ == "__main__":
    main()
