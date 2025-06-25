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
        """Builds the Semgrep rule from a template and the JSON output from the LLM."""
        if not (output and output.is_valid and 'patterns' in output.output and output.output['patterns']):
            return None

        try:
            with open(self.template_path, 'r') as f:
                template_content = f.read()

            rule_components = output.output
            
            # Safely dump string values to handle special characters
            rule_id = yaml.dump(rule_components.get('id', 'dynamic-rule-id'))
            message = yaml.dump(rule_components.get('message', 'Dynamic rule message.'))
            severity = yaml.dump(rule_components.get('severity', 'WARNING'))
            
            # Convert patterns dict to a YAML string with proper indentation
            patterns_yml = yaml.dump(rule_components['patterns'], indent=4).strip()
            
            # Replace placeholders in the template
            final_rule = template_content.replace('<RULE_ID>', rule_id.strip())
            final_rule = final_rule.replace('<MESSAGE>', message.strip())
            final_rule = final_rule.replace('<SEVERITY>', severity.strip())
            final_rule = final_rule.replace('<PATTERNS>', patterns_yml)
            
            # A simple check to ensure it looks like a valid rule
            yaml.safe_load(final_rule)

            return final_rule
        except FileNotFoundError:
            print(f"Error: Template file not found at {self.template_path}")
            return None
        except (yaml.YAMLError, KeyError) as e:
            print(f"Error building final rule from template: {e}")
            return None
        except Exception as e:
            print(f"An unexpected error occurred in get_rule: {e}")
            return None 