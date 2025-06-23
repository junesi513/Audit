from tstool.analyzer.TS_analyzer import *
from tstool.analyzer.Java_TS_analyzer import *
from tstool.dfbscan_extractor.dfbscan_extractor import DFBScanExtractor
from memory.syntactic.value import Value, ValueLabel
import tree_sitter
from pathlib import Path

class Java_CWE20_extractor(DFBScanExtractor):
    def __init__(self, ts_analyzer: TSAnalyzer) -> None:
        super().__init__(ts_analyzer)
        self.java_parser = tree_sitter.Parser()
        
        # Correctly calculate the path to the language library
        cwd = Path(__file__).resolve().parent.absolute()
        language_path = cwd / "../../../../lib/build/my-languages.so"
        java_lang = tree_sitter.Language(str(language_path), "java")
        
        self.java_parser.set_language(java_lang)

    def extract_all(self):
        """
        Overrides the base implementation to directly parse ASTs for sources and sinks,
        bypassing the pre-processed function_env for greater accuracy.
        """
        sources = []
        sinks = []

        # Query to find classes implementing ObjectDeserializer
        class_query_str = """
        (class_declaration
          (super_interfaces
            (type_list
              (type_identifier) @iname
              (#eq? @iname "ObjectDeserializer")
            )
          )
          body: (class_body) @class_body
        )
        """
        class_query = self.ts_analyzer.language.query(class_query_str)

        for file_path, source_code in self.ts_analyzer.code_in_files.items():
            tree = self.java_parser.parse(bytes(source_code, "utf8"))
            captures = class_query.captures(tree.root_node)

            for node, name in captures:
                if name == "class_body":
                    class_body_node = node
                    
                    # Query to find the 'deserialze' method within this class
                    method_query_str = """
                    (method_declaration
                      name: (identifier) @mname
                      parameters: (formal_parameters) @params
                      body: (block) @mbody
                      (#eq? @mname "deserialze")
                    )
                    """
                    method_query = self.ts_analyzer.language.query(method_query_str)
                    method_captures = method_query.captures(class_body_node)

                    deserialze_method_body = None
                    for m_node, m_name in method_captures:
                        if m_name == "params":
                            # Found the source method, extract its parameters
                            param_nodes = find_nodes_by_type(m_node, "formal_parameter")
                            for index, param_node in enumerate(param_nodes):
                                param_name_node = find_nodes_by_type(param_node, "identifier")[-1]
                                param_name = source_code[param_name_node.start_byte:param_name_node.end_byte]
                                line = param_name_node.start_point[0] + 1
                                sources.append(Value(param_name, line, ValueLabel.PARA, file_path, index))
                        
                        if m_name == "mbody":
                            deserialze_method_body = m_node

                    if deserialze_method_body:
                        # Query to find 'parseArray' calls within the method
                        sink_query_str = """
                        (method_invocation
                          name: (identifier) @sink_name
                          (#eq? @sink_name "parseArray")
                        ) @sink_invocation
                        """
                        sink_query = self.ts_analyzer.language.query(sink_query_str)
                        sink_captures = sink_query.captures(deserialze_method_body)

                        for s_node, s_name in sink_captures:
                            if s_name == "sink_invocation":
                                line = s_node.start_point[0] + 1
                                name = source_code[s_node.start_byte:s_node.end_byte]
                                sinks.append(Value(name, line, ValueLabel.SINK, file_path))
        
        self.sources = sources
        self.sinks = sinks
        return self.sources, self.sinks

    def extract_sources(self, function: Function) -> List[Value]:
        # This method is now bypassed by the custom extract_all()
        return []

    def extract_sinks(self, function: Function) -> List[Value]:
        # This method is now bypassed by the custom extract_all()
        return [] 