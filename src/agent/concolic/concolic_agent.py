import yaml
from pathlib import Path
import re

from src.agent.agent import Agent
from src.llmtool.concolic.hypothesis_generator import HypothesisGenerator
from src.llmtool.concolic.semgrep_generator import SemgrepGenerator
from src.memory.semantic.dfbscan_state import DFBScanState
from src.tstool.analyzer.Java_TS_analyzer import JavaTSAnalyzer
from src.ui.logger import Logger
from src.memory.report.bug_report import BugReport

class ConcolicAgent(Agent):
    def __init__(self, props):
        super().__init__()
        self.logger = props.get("logger")
        self.hypothesis_generator = HypothesisGenerator(
            language=props.get('language'),
            model_name=props.get('model_name'),
            api_key=props.get('api_key')
        )
        self.semgrep_generator = SemgrepGenerator(
            language=props.get('language'),
            model_name=props.get('model_name'),
            api_key=props.get('api_key')
        )
        self.bug_type = props.get("bug_type", "CWE20")
        self.ts_analyzer = JavaTSAnalyzer(code_in_files={})

    def _find_ast_nodes(self, root_node, node_info_list):
        """Finds AST nodes based on the type and name information from LLM."""
        found_nodes = []
        for info in node_info_list:
            if not isinstance(info, dict):
                continue

            node_type = info.get("node_type")
            node_name = info.get("node_name")
            if not node_type or not node_name:
                continue
            
            # More precise recursive search
            q = [root_node]
            while q:
                curr = q.pop(0)
                # Primary check: node type matches
                if curr.type == node_type:
                    # Secondary check: node's own identifier or name matches.
                    # This is more robust than checking `in curr.text`.
                    
                    # Check for a 'name' field, common in declarations
                    name_node = curr.child_by_field_name('name')
                    if name_node and name_node.text.decode('utf8') == node_name:
                        found_nodes.append(curr)
                        continue # Found, so no need to check other conditions or children

                    # Check for an 'identifier' child, common in other expressions
                    for child in curr.children:
                        # Sometimes the identifier is nested, e.g., in `scoped_identifier`
                        if child.type == 'identifier' and child.text.decode('utf8') == node_name:
                            found_nodes.append(curr)
                            break # Found for this `curr`
                        # Handle cases like "qualifier.identifier"
                        if 'identifier' in child.type: 
                             id_nodes = self._find_nodes_by_types(child, ['identifier'])
                             if any(id_node.text.decode('utf8') == node_name for id_node in id_nodes):
                                 found_nodes.append(curr)
                                 break # Found for this `curr`

                # If not found at this level, continue searching children
                q.extend(curr.children)
        # Remove duplicates
        return list(dict.fromkeys(found_nodes))

    def _find_nodes_by_types(self, node, types):
        if not isinstance(types, list):
            types = [types]
        q = [node]
        nodes = []
        while q:
            curr = q.pop(0)
            if curr.type in types:
                nodes.append(curr)
            q.extend(curr.children)
        return nodes

    def _get_all_identifiers(self, node):
        """Recursively find all identifier nodes under a given node."""
        if not node:
            return []
        return self._find_nodes_by_types(node, ['identifier'])

    def _simple_taint_analysis(self, source_nodes, sink_nodes, root_node) -> bool:
        if not source_nodes or not sink_nodes:
            return False

        # 1. Initialize tainted variables from source nodes
        tainted_vars = set()
        for node in source_nodes:
            # Heuristic: find all identifiers in the source node and consider them tainted
            name_nodes = self._get_all_identifiers(node)
            for name_node in name_nodes:
                tainted_vars.add(name_node.text.decode('utf8'))

        if not tainted_vars:
            self.logger.print_console("No initial tainted variables found from sources.", "debug")
            return False
        
        self.logger.print_console(f"Initial tainted variables: {tainted_vars}", "debug")

        # 2. Taint Propagation using a worklist
        worklist = list(tainted_vars)
        
        method_body = root_node.child_by_field_name('body')
        if not method_body:
            return False
            
        processed_nodes = set() # To avoid infinite loops

        while worklist:
            var_to_check = worklist.pop(0)
            
            # Find all assignments and declarations in the method body
            nodes_to_check = self._find_nodes_by_types(method_body, ['assignment_expression', 'variable_declarator'])
            
            for node in nodes_to_check:
                if node in processed_nodes:
                    continue

                if node.type == 'assignment_expression':
                    left_node = node.child_by_field_name('left')
                    right_node = node.child_by_field_name('right')
                elif node.type == 'variable_declarator':
                    left_node = node.child_by_field_name('name')
                    right_node = node.child_by_field_name('value')
                else:
                    continue

                if not left_node or not right_node:
                    continue
                
                right_identifiers = {id_node.text.decode('utf8') for id_node in self._get_all_identifiers(right_node)}
                
                # Also check for method invocations where a tainted var is an argument
                is_tainted_by_call = False
                if right_node.type == 'method_invocation':
                    argument_list = right_node.child_by_field_name('arguments')
                    if argument_list:
                        arg_identifiers = {id_node.text.decode('utf8') for id_node in self._get_all_identifiers(argument_list)}
                        if not arg_identifiers.isdisjoint({var_to_check}):
                            is_tainted_by_call = True

                if var_to_check in right_identifiers or is_tainted_by_call:
                    # new variable is tainted
                    # assuming left is a simple identifier for assignment, which might not be true (e.g., a.b)
                    new_tainted_var_name = left_node.text.decode('utf8').strip()
                    if new_tainted_var_name and new_tainted_var_name not in tainted_vars:
                        self.logger.print_console(f"Taint propagated: {var_to_check} -> {new_tainted_var_name}", "debug")
                        tainted_vars.add(new_tainted_var_name)
                        worklist.append(new_tainted_var_name)
                    processed_nodes.add(node)

        self.logger.print_console(f"Final tainted set: {tainted_vars}", "debug")

        # 3. Check if any sink node uses a tainted variable
        for node in sink_nodes:
            sink_identifiers = {id_node.text.decode('utf8') for id_node in self._get_all_identifiers(node)}
            # Check for intersection
            if not tainted_vars.isdisjoint(sink_identifiers):
                tainted_in_sink = tainted_vars.intersection(sink_identifiers)
                self.logger.print_console(f"Taint flow VALIDATED: Tainted vars {tainted_in_sink} used in sink '{node.text.decode('utf8')}'", "info")
                return True

        return False


    def run_agent(self, state: DFBScanState):
        target_file_path = state.target_path
        self.logger.print_console(f"Concolic agent (AST mode) is running on file: {target_file_path}", "info")
        
        try:
            with open(target_file_path, 'r', encoding='utf-8') as f:
                source_code = f.read()
        except Exception as e:
            self.logger.print_console(f"Failed to read file {target_file_path}: {e}", "error")
            return

        self.ts_analyzer.extract_function_info_from_code(file_path=target_file_path, source_code=source_code)
        
        if not self.ts_analyzer.functionRawDataDic:
            self.logger.print_console(f"No methods found in {target_file_path}. Skipping.", "info")
            return
        
        self.logger.print_console(f"Found {len(self.ts_analyzer.functionRawDataDic)} methods to analyze.", "info")

        for func_id, (func_name, start_line, end_line, ast_node) in self.ts_analyzer.functionRawDataDic.items():
            self.logger.print_console(f"Analyzing method: {func_name}", "info")

            function_code = ast_node.text.decode('utf8', 'ignore')
            
            # 1. Generate hypothesis
            hypo_output = self.hypothesis_generator.generate(function_code)
            if not hypo_output.is_valid or not hypo_output.output:
                self.logger.print_console(f"Hypothesis generation failed for '{func_name}'. Skipping.", "warn")
                if hypo_output.error_message:
                    self.logger.print_console(f"Error: {hypo_output.error_message}", "debug")
                if hypo_output.raw_output:
                    self.logger.print_console(f"LLM Raw Output:\n---\n{hypo_output.raw_output}\n---", "debug")
                continue
            
            vul_hypo_dict = hypo_output.output
            vul_hypo_str = vul_hypo_dict.get('vulnerability_hypothesis', '')
            if not isinstance(vul_hypo_str, str) or not vul_hypo_str:
                self.logger.print_console(f"Invalid hypothesis for '{func_name}'. Skipping.", "warn")
                continue

            # 2. Get taint flow patterns from LLM with self-correction
            MAX_ATTEMPTS = 3
            last_error = None
            taint_patterns = None
            
            for attempt in range(MAX_ATTEMPTS):
                self.logger.print_console(f"Attempt {attempt + 1}/{MAX_ATTEMPTS} to get taint patterns for '{func_name}'.", "debug")
                
                taint_flow_output = self.semgrep_generator.generate(
                    function_code=function_code,
                    vulnerability_hypothesis=vul_hypo_str,
                    previous_error=last_error
                )

                if not taint_flow_output.is_valid or not taint_flow_output.output:
                    self.logger.print_console(f"Taint pattern generation failed on attempt {attempt + 1}.", "warn")
                    last_error = taint_flow_output.error_message or "Generation failed without a specific error message."
                    continue

                taint_patterns = taint_flow_output.output
                source_info = taint_patterns.get("source", [])
                sink_info = taint_patterns.get("sink", [])

                if not source_info or not sink_info:
                    last_error = "LLM did not provide both source and sink information."
                    self.logger.print_console(last_error, "debug")
                    taint_patterns = None # Reset for next attempt
                    continue

                # Validate if nodes can be found
                source_nodes = self._find_ast_nodes(ast_node, source_info)
                sink_nodes = self._find_ast_nodes(ast_node, sink_info)

                if source_nodes and sink_nodes:
                    self.logger.print_console(f"Successfully found source/sink nodes for '{func_name}'.", "info")
                    break # Success
                else:
                    last_error = f"Could not find AST nodes. Found {len(source_nodes)} sources and {len(sink_nodes)} sinks. Please provide different node information."
                    self.logger.print_console(last_error, "debug")
                    taint_patterns = None # Reset for next attempt
            
            if not taint_patterns:
                self.logger.print_console(f"Failed to get valid taint patterns for '{func_name}' after {MAX_ATTEMPTS} attempts. Skipping.", "error")
                continue
            
            # From here, we assume source_info, sink_info, source_nodes, sink_nodes are valid
            source_info = taint_patterns.get("source", [])
            sink_info = taint_patterns.get("sink", [])
            source_nodes = self._find_ast_nodes(ast_node, source_info)
            sink_nodes = self._find_ast_nodes(ast_node, sink_info)

            # 3. Find AST nodes and perform analysis
            # source_nodes = self._find_ast_nodes(ast_node, source_info) # Already done above
            # sink_nodes = self._find_ast_nodes(ast_node, sink_info) # Already done above

            self.logger.print_console(f"Source nodes found: {len(source_nodes)}", "debug")
            self.logger.print_console(f"Sink nodes found: {len(sink_nodes)}", "debug")
            
            if self._simple_taint_analysis(source_nodes, sink_nodes, ast_node):
                self.logger.print_console(f"Vulnerability VALIDATED for method '{func_name}' in {target_file_path}", "info")
                
            report = BugReport(
                    cwe_id=self.bug_type,
                    file_path=target_file_path,
                    function_name=func_name,
                    start_line=start_line,
                    end_line=end_line,
                    explanation=str(vul_hypo_dict),
                    details={"taint_source_info": source_info, "taint_sink_info": sink_info}
                )
                report_path = Path("reports") / self.bug_type
                report_path.mkdir(parents=True, exist_ok=True)
                report_file = report_path / f"{func_name.replace(' ', '_')}-{self.bug_type}.json"
                report.dump(report_file.parent, report_file.name)
                self.logger.print_console(f"Bug report for '{func_name}' saved to {report_file}", "info")
        else:
                self.logger.print_console(f"Hypothesis NOT validated for method '{func_name}'.", "info")
        
        self.logger.print_console("Concolic agent has finished analyzing all methods.", "info")

    def run(self):
        pass

    def get_agent_state(self):
        return None

# Ensure necessary directories exist
Path("src/semgrep").mkdir(exist_ok=True)
Path("src/semgrep_rules").mkdir(exist_ok=True) 