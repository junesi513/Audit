from os import path
import sys

sys.path.append(path.dirname(path.dirname(path.dirname(path.abspath(__file__)))))
from src.tstool.analyzer.ts_analyzer import *
from src.memory.syntactic.function import *
from src.memory.syntactic.value import *
from src.memory.report.bug_report import *
from src.memory.semantic.state import *
from typing import List, Tuple, Dict


class DFBScanState(State):
    def __init__(self, **kwargs) -> None:
        # Dynamically set attributes from kwargs
        for key, value in kwargs.items():
            setattr(self, key, value)

        # Initialize core attributes if they weren't provided
        if not hasattr(self, 'src_values'):
            self.src_values = []
        if not hasattr(self, 'sink_values'):
            self.sink_values = []
        if not hasattr(self, 'potential_buggy_paths'):
            self.potential_buggy_paths = {}
        if not hasattr(self, 'bug_reports'):
            self.bug_reports = {}
        if not hasattr(self, 'total_bug_count'):
            self.total_bug_count = 0
        
        # For concolic agent state tracking
        if not hasattr(self, 'history'):
            self.history = []
        if not hasattr(self, 'validated'):
            self.validated = False

        self.reachable_values_per_path: Dict[
            Tuple[Value, CallContext], List[Set[Tuple[Value, CallContext]]]
        ] = {}
        self.external_value_match: Dict[
            Tuple[Value, CallContext], Set[Tuple[Value, CallContext]]
        ] = {}

    def add_hypothesis(self, hypothesis: str):
        self.history.append({'type': 'hypothesis', 'content': hypothesis})

    def set_validated(self):
        self.validated = True

    def update_reachable_values_per_path(
        self, start: Tuple[Value, CallContext], ends: Set[Tuple[Value, CallContext]]
    ) -> None:
        """
        Update the reachable values per path
        """
        if start not in self.reachable_values_per_path:
            self.reachable_values_per_path[start] = []
        self.reachable_values_per_path[start].append(ends)
        return

    def update_external_value_match(
        self,
        external_start: Tuple[Value, CallContext],
        external_ends: Set[Tuple[Value, CallContext]],
    ) -> None:
        """
        Update the external value match
        """
        if external_start not in self.external_value_match:
            self.external_value_match[external_start] = set()
        self.external_value_match[external_start].update(external_ends)
        return

    def update_potential_buggy_paths(self, src_value: Value, path: List[Value]) -> None:
        """
        Update the buggy paths
        """
        if src_value not in self.potential_buggy_paths:
            self.potential_buggy_paths[src_value] = {}
        self.potential_buggy_paths[src_value][str(path)] = path
        return

    def update_bug_report(self, bug_report: BugReport) -> None:
        """
        Update the bug scan state with the bug report
        :param bug_report: the bug report
        """
        self.bug_reports[self.total_bug_count] = bug_report
        self.total_bug_count += 1
        return

    def print_reachable_values_per_path(self) -> None:
        """
        Print the reachable values per path
        """
        print("=====================================")
        print("Reachable Values Per Path:")
        print("=====================================")
        for (
            start_value,
            start_context,
        ), ends in self.reachable_values_per_path.items():
            print("-------------------------------------")
            print(f"Start: {str(start_value)}, {str(start_context)}")
            for i in range(len(ends)):
                print("--------------------------")
                print(f"  Path {i + 1}:")
                for value, ctx in ends[i]:
                    print(f"  End: {value}, {str(ctx)}")
                print("--------------------------")
            print("-------------------------------------")
        print("=====================================\n")
        return

    def print_external_value_match(self) -> None:
        """
        Print the external value match.
        """
        print("=====================================")
        print("External Value Match:")
        print("=====================================")
        for start, ends in self.external_value_match.items():
            print("-------------------------------------")
            print(f"Start: {start[0]}, {str(start[1])}")
            for end in ends:
                # end is a tuple of (Value, CallContext)
                print(f"  End: {end[0]}, {str(end[1])}")
            print("-------------------------------------")
        print("=====================================\n")
        return

    def print_potential_buggy_paths(self) -> None:
        """
        Print the potential buggy paths
        """
        print("=====================================")
        print("Potential Buggy Paths:")
        print("=====================================")
        for src_value, paths in self.potential_buggy_paths.items():
            print("-------------------------------------")
            print(f"Source Value: {src_value}")
            for path_str, path in paths.items():
                print(f"Path: {path_str}")
                print(f"  Path: {path}")
            print("-------------------------------------")
        return
