from os import path
import sys
from typing import Dict, List, Set, Tuple

import tree_sitter

from src.tstool.analyzer.ts_analyzer import TSAnalyzer, find_nodes_by_type
from src.memory.syntactic.function import Function
from src.memory.syntactic.value import Value, ValueLabel

sys.path.append(path.dirname(path.dirname(path.abspath(__file__))))

class JavaTSAnalyzer(TSAnalyzer):
    def __init__(self, code_in_files: dict = None):
        super().__init__(code_in_files, "Java")

    def find_nodes_by_type(self, node, node_type):
        return find_nodes_by_type(node, node_type)

    def extract_function_info(
        self, file_path: str, source_code: str, tree: tree_sitter.Tree
    ) -> None:
        query_str = """
        (method_declaration
            name: (identifier) @name
        ) @method
        """
        query = self.language.query(query_str)
        captures = query.captures(tree.root_node)

        method_name_map = {}
        for node, tag in captures:
            if tag == 'method':
                method_name_map[node.id] = None
            elif tag == 'name':
                parent_method = node.parent
                if parent_method.id in method_name_map:
                    method_name_map[parent_method.id] = node

        for method_id, name_node in method_name_map.items():
            if name_node:
                method_node = tree.root_node.descendant_for_byte_range(method_id, method_id)
                function_name = name_node.text.decode('utf8')
                start_line_number = method_node.start_point[0] + 1
                end_line_number = method_node.end_point[0] + 1
                
                if function_name not in self.functionNameToId:
                    self.functionNameToId[function_name] = []
                
                current_function_id = len(self.functionRawDataDic)
                self.functionRawDataDic[current_function_id] = (
                    function_name,
                    start_line_number,
                    end_line_number,
                    method_node,
                )
                self.functionNameToId[function_name].append(current_function_id)
                self.functionToFile[current_function_id] = file_path

    def extract_function_info_from_code(self, file_path: str, source_code: str) -> None:
        tree = self.parser.parse(bytes(source_code, "utf8"))
        self.extract_function_info(file_path, source_code, tree)

    def extract_global_info(self, file_path: str, source_code: str, tree: tree_sitter.Tree) -> None:
        # Java does not have global variables or macros in the same way as C/Cpp,
        # but you can have public static fields.
        # This implementation can be extended to find them if needed.
        pass

    def get_callee_name_at_call_site(self, node: tree_sitter.Node, source_code: str) -> str:
        if node.type == "method_invocation":
            name_node = node.child_by_field_name("name")
            if name_node:
                return name_node.text.decode('utf8')
            
            # Handling for more complex calls like object.method()
            obj_node = node.child_by_field_name("object")
            if obj_node:
                name_node = node.children[-1] # name is usually the last child
                if name_node.type == 'identifier':
                    return name_node.text.decode('utf8')
        return ""

    def get_callsites_by_callee_name(self, current_function: Function, callee_name: str) -> List[tree_sitter.Node]:
        results = []
        file_content = self.fileContentDic[current_function.file_path]
        call_site_nodes = find_nodes_by_type(
            current_function.parse_tree_root_node, "method_invocation"
        )
        for call_site in call_site_nodes:
            if (self.get_callee_name_at_call_site(call_site, file_content) == callee_name):
                results.append(call_site)
        return results

    def get_arguments_at_callsite(self, current_function: Function, call_site_node: tree_sitter.Node) -> Set[Value]:
        arguments = set()
        file_name = current_function.file_path
        source_code = self.fileContentDic[file_name]
        
        argument_list_node = call_site_node.child_by_field_name("arguments")
        if not argument_list_node:
            return arguments
            
        index = 0
        for arg_node in argument_list_node.children:
            if arg_node.type not in ['(', ')', ',']:
                line_number = arg_node.start_point[0] + 1
                arg_text = arg_node.text.decode('utf8')
                arguments.add(
                    Value(
                        arg_text,
                        line_number,
                        ValueLabel.ARG,
                        file_name,
                        index
                    )
                )
                index += 1
        return arguments

    def get_parameters_in_single_function(self, current_function: Function) -> Set[Value]:
        parameters = set()
        
        param_list_node = find_nodes_by_type(current_function.parse_tree_root_node, "formal_parameters")
        if not param_list_node:
            return parameters
            
        param_list_node = param_list_node[0]

        index = 0
        for param_node in param_list_node.children:
            if param_node.type == "formal_parameter":
                param_name_node = param_node.child_by_field_name("name")
                if param_name_node:
                    line_number = param_name_node.start_point[0] + 1
                    param_name = param_name_node.text.decode('utf8')
                    parameters.add(
                        Value(
                            param_name,
                            line_number,
                            ValueLabel.PARA,
                            current_function.file_path,
                            index,
                        )
                    )
                    index +=1
        return parameters

    def get_return_values_in_single_function(self, current_function: Function) -> Set[Value]:
        ret_values = set()
        file_content = self.fileContentDic[current_function.file_path]
        ret_nodes = find_nodes_by_type(current_function.parse_tree_root_node, "return_statement")
        
        for ret_node in ret_nodes:
            line_number = ret_node.start_point[0] + 1
            if len(ret_node.children) > 1:
                value_node = ret_node.children[1] # 'return' is child 0
                ret_text = value_node.text.decode('utf8')
                ret_values.add(
                    Value(
                        ret_text,
                        line_number,
                        ValueLabel.RET,
                        current_function.file_path,
                        0 
                    )
                )
        return ret_values

    def get_if_statements(self, function: Function, source_code: str) -> Dict[Tuple, Tuple]:
        if_statements = {}
        if_nodes = find_nodes_by_type(function.parse_tree_root_node, "if_statement")
        
        for if_node in if_nodes:
            start_line = if_node.start_point[0] + 1
            end_line = if_node.end_point[0] + 1
            
            condition_node = if_node.child_by_field_name("condition")
            consequence_node = if_node.child_by_field_name("consequence")
            alternative_node = if_node.child_by_field_name("alternative")

            condition_str = condition_node.text.decode('utf8')
            condition_start_line = condition_node.start_point[0] + 1
            condition_end_line = condition_node.end_point[0] + 1
            
            true_branch_start_line = consequence_node.start_point[0] + 1
            true_branch_end_line = consequence_node.end_point[0] + 1

            else_branch_start_line = 0
            else_branch_end_line = 0
            if alternative_node:
                # remove 'else' keyword
                else_block = alternative_node.children[1] if alternative_node.children[0].type == 'else' else alternative_node.children[0]
                else_branch_start_line = else_block.start_point[0] + 1
                else_branch_end_line = else_block.end_point[0] + 1

            if_statements[(start_line, end_line)] = (
                 condition_str,
                 condition_start_line,
                 condition_end_line,
                 (true_branch_start_line, true_branch_end_line),
                 (else_branch_start_line, else_branch_end_line),
            )
        return if_statements

    def get_loop_statements(self, function: Function, source_code: str) -> Dict[Tuple, Tuple]:
        loop_statements = {}
        loop_types = ["for_statement", "while_statement", "do_statement", "enhanced_for_statement"]
        
        for loop_type in loop_types:
            loop_nodes = find_nodes_by_type(function.parse_tree_root_node, loop_type)
            for loop_node in loop_nodes:
                start_line = loop_node.start_point[0] + 1
                end_line = loop_node.end_point[0] + 1
                body_node = loop_node.child_by_field_name("body")
                body_start_line = body_node.start_point[0] + 1
                body_end_line = body_node.end_point[0] + 1

                loop_statements[(start_line, end_line)] = (
                    loop_node.type,
                    loop_node.text.decode('utf8'),
                    body_node.text.decode('utf8'),
                    body_start_line,
                    body_end_line
                )
        return loop_statements
