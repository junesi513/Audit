import sys
from os import path

sys.path.append(path.dirname(path.dirname(path.dirname(path.abspath(__file__)))))

from src.tstool.analyzer.TS_analyzer import *
from src.tstool.analyzer.Java_TS_analyzer import *
from src.tstool.dfbscan_extractor.dfbscan_extractor import DFBScanExtractor
from src.memory.syntactic.value import Value, ValueLabel
import tree_sitter
from pathlib import Path

class Java_ImproperValidation_extractor(DFBScanExtractor):
    def __init__(self, ts_analyzer: TSAnalyzer) -> None:
        super().__init__(ts_analyzer)
        self.java_parser = tree_sitter.Parser()
        
        # Correctly calculate the path to the language library
        cwd = Path(__file__).resolve().parent.absolute()
        language_path = cwd / "../../../../lib/build/my-languages.so"
        java_lang = tree_sitter.Language(str(language_path), "java")
        
        self.java_parser.set_language(java_lang)
        self.extractor_name = "Java_ImproperValidation_extractor"

    def extract_sources(self) -> List[Value]:
        # Let's redefine the source back to the original entry point of the function
        # to trace the full path to the sink-argument.
        sources = []
        # Query to find the 'deserialze' method
        query_str = """
        (method_declaration
           name: (identifier) @mname
           parameters: (formal_parameters (formal_parameter
            type: (type_identifier) @ptype
            name: (identifier) @pname
            (#eq? @ptype "Type")
           ))
           (#eq? @mname "deserialze")
        )
        """
        query = self.ts_analyzer.language.query(query_str)
        for file_path, tree in self.ts_analyzer.parse_trees.items():
            captures = query.captures(tree.root_node)
            for node, name in captures:
                if name == 'pname':
                    param_name = node.text.decode('utf8')
                    line = node.start_point[0] + 1
                    sources.append(Value(param_name, line, ValueLabel.PARA, file_path))
        return sources

    def extract_sinks(self, function_node: Function) -> List[Value]:
        """
        Identifies the *first argument* of 'parseArray' calls as the sink.
        This argument is the "input vector" to the critical object.
        """
        sinks = []
        # Query to find method invocations named 'parseArray'
        query_str = """
        (method_invocation
            name: (identifier) @method_name
            arguments: (argument_list) @args
            (#eq? @method_name "parseArray")
        ) @invocation
        """
        query = self.ts_analyzer.language.query(query_str)
        captures = query.captures(function_node.parse_tree_root_node)

        for node, name in captures:
            if name == 'args':
                # We have the argument list. Get the first argument.
                if node.child_count > 0:
                    first_arg_node = node.children[0]
                    
                    # The argument itself might be an expression, but we want the variable name.
                    # A simple approach is to take the text of the node.
                    sink_name = first_arg_node.text.decode('utf8')
                    line_number = first_arg_node.start_point[0] + 1
                    file_path = function_node.file_path
                    
                    # Define this argument as the SINK
                    sink_val = Value(sink_name, line_number, ValueLabel.SINK, file_path)
                    sinks.append(sink_val)
        return sinks

    def extract_all(self) -> Tuple[List[Value], List[Value]]:
        sources = self.extract_sources()
        
        all_sinks = []
        functions = self.ts_analyzer.function_env.values()
        for func in functions:
            all_sinks.extend(self.extract_sinks(func))
            
        return sources, all_sinks 