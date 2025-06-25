import sys
from os import path
from pathlib import Path
import re
import json
import yaml

sys.path.append(path.dirname(path.dirname(path.dirname(path.abspath(__file__)))))

from src.llmtool.LLM_utils import LLM, Prompt, LLMToolOutput

class SemgrepGenerator:
    def __init__(self, model_name: str, language: str, api_key: str = None, temperature: float = 0.0, **kwargs):
        self.language = language
        base_path = Path(__file__).resolve().parents[3]
        self.prompt_path = f"{base_path}/src/prompt/{self.language.capitalize()}/concolic/semgrep_generator.json"
        self.template_path = f"{base_path}/src/semgrep_rules/java_taint_template.yml"
        self.prompt = Prompt(self.prompt_path)
        self.model = LLM(model_name=model_name, api_key=api_key, temperature=temperature)

    def generate(self, function_code: str, vulnerability_hypothesis: str, previous_error: str = None) -> LLMToolOutput:
        inputs = {
            'FUNC_CODE': function_code,
            'VULN_HYPOTHESIS': vulnerability_hypothesis
        }
        if previous_error:
            inputs['PREVIOUS_ERROR'] = previous_error

        prompt_str = self.prompt.get_string_with_inputs(inputs)
        raw_output = self.model.generate(prompt_str)
        return self._post_process(raw_output)

    def _post_process(self, llm_response_content: str) -> LLMToolOutput:
        """Processes the raw LLM output string to extract the Semgrep rule components as JSON."""
        try:
            json_match = re.search(r"```json\n(.*?)\n```", llm_response_content, re.DOTALL)
            if json_match:
                json_content = json_match.group(1)
                # Let's validate if it's a valid JSON
                parsed_json = json.loads(json_content)
                return LLMToolOutput(is_valid=True, output=parsed_json)
        except json.JSONDecodeError as e:
            return LLMToolOutput(is_valid=False, error_message=f"LLM produced invalid JSON: {e}")
        except Exception as e:
            return LLMToolOutput(is_valid=False, error_message=f"An unexpected error occurred during post-processing: {e}")
        
        return LLMToolOutput(is_valid=False, error_message="Could not extract JSON from LLM output.")

    def get_rule(self, output: LLMToolOutput) -> str | None:
        """Builds a robust Semgrep rule by loading a template and programmatically inserting validated patterns."""
        if not (output and output.is_valid and output.output):
            return None

        def is_valid_pattern(p_str: str) -> bool:
            """A simple validation function to filter out clearly invalid patterns."""
            if not p_str or not p_str.strip():
                return False
            # Filter out patterns that are just single special characters or too short
            if len(p_str.strip()) <= 2 and not p_str.strip().isalnum():
                return False
            return True

        patterns = output.output
        
        # Safely get lists, defaulting to an empty list if the key is missing or the value is None.
        sources = list(filter(is_valid_pattern, patterns.get("source") or []))
        sinks = list(filter(is_valid_pattern, patterns.get("sink") or []))
        sanitizers = list(filter(is_valid_pattern, patterns.get("sanitizer") or []))

        # A taint rule is meaningless without at least one valid source and one valid sink.
        if not sources or not sinks:
            print("Skipping rule generation: No valid source or sink patterns found after validation.")
            return None

        try:
            with open(self.template_path, 'r') as f:
                # Load the base rule structure from the template
                rule_template = yaml.safe_load(f)

            # Prepare pattern dictionaries
            source_patterns = [{'pattern': p} for p in sources]
            sink_patterns = [{'pattern': p} for p in sinks]
            sanitizer_patterns = [{'pattern': p} for p in sanitizers]
            
            # Programmatically insert the patterns into the rule structure
            # Assumes the template has a single rule in the `rules` list
            rule_template['rules'][0]['pattern-sources'] = source_patterns
            rule_template['rules'][0]['pattern-sinks'] = sink_patterns
            rule_template['rules'][0]['pattern-sanitizers'] = sanitizer_patterns

            # Convert the final rule object back to a YAML string
            final_rule = yaml.dump(rule_template)

            return final_rule
        except FileNotFoundError:
            print(f"Error: Template file not found at {self.template_path}")
            return None
        except (yaml.YAMLError, KeyError, IndexError) as e:
            print(f"Error processing rule template or inserting patterns: {e}")
            return None
        except Exception as e:
            print(f"An unexpected error occurred in get_rule: {e}")
            return None 