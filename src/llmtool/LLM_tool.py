from __future__ import annotations
from llmtool.LLM_utils import *
from abc import ABC, abstractmethod
from typing import Dict, List, Tuple
from ui.logger import Logger
from dataclasses import dataclass
from memory.syntactic.function import Function
from memory.syntactic.value import Value
from llmtool.LLM_utils import LLM


class LLMToolInput(ABC):
    def __init__(self):
        pass

    @abstractmethod
    def __hash__(self):
        pass

    def __eq__(self, value):
        return self.__hash__() == value.__hash__()


class LLMToolOutput(ABC):
    def __init__(self):
        pass


class LLMTool(ABC):
    def __init__(
        self,
        model_name: str,
        temperature: float,
        language: str,
        max_query_num: int,
        logger: Logger
    ) -> None:
        self.language = language
        self.model_name = model_name
        self.temperature = temperature
        self.language = language
        self.max_query_num = max_query_num
        self.logger = logger

        self.model = LLM(
            model_name=self.model_name,
            temperature=self.temperature,
            system_role=self.system_role,
            logger=self.logger
        )
        self.cache: Dict[LLMToolInput, LLMToolOutput] = {}

        self.input_token_cost = 0
        self.output_token_cost = 0
        self.total_query_num = 0

    def invoke(self, input: LLMToolInput) -> LLMToolOutput:
        class_name = type(self).__name__
        self.logger.print_console(f"The LLM Tool {class_name} is invoked.")
        if input in self.cache:
            self.logger.print_log("Cache hit.")
            return self.cache[input]

        prompt = self._get_prompt(input)
        self.logger.print_log("\\n" + "="*50 + "\\nPROMPT:\\n" + "="*50 + "\\n" + prompt)

        single_query_num = 0
        output = None
        while True:
            if single_query_num > self.max_query_num:
                break
            single_query_num += 1
            response, input_token_cost, output_token_cost = self.model.infer(
                prompt, True
            )
            self.logger.print_log("\\n" + "="*50 + "\\nRESPONSE:\\n" + "="*50 + "\\n" + response)
            
            self.input_token_cost += input_token_cost
            self.output_token_cost += output_token_cost
            output = self._parse_response(response, input)

            if output is not None:
                break

        self.total_query_num += single_query_num
        if output is not None:
            self.cache[input] = output
        return output

    @abstractmethod
    def _get_prompt(self, input: LLMToolInput) -> str:
        pass

    @abstractmethod
    def _parse_response(
        self, response: str, input: LLMToolInput = None
    ) -> LLMToolOutput:
        pass


@dataclass
class IntraDataFlowAnalyzerInput(LLMToolInput):
    function: Function
    src_value: Value
    sink_values: List[Tuple[str, int]]
    call_statements: List[Tuple[str, int]]
    ret_values: List[Tuple[str, int]]
    local_vars: List[str]
    assignments: List[str]

    def __hash__(self):
        return hash((self.function.name, self.src_value.name, tuple(self.sink_values)))


@dataclass
class IntraDataFlowAnalyzerOutput(LLMToolOutput):
    reachable_values: List[List[Value]]


@dataclass
class PathValidatorInput(LLMToolInput):
    bug_type: str
    path: Tuple
    funcs: Dict[Value, Function]


@dataclass
class PathValidatorOutput(LLMToolOutput):
    is_reachable: bool
    explanation_str: str


@dataclass
class StepTracerInput(LLMToolInput):
    variable: Value
    code_snippet: str


@dataclass
class StepTracerOutput(LLMToolOutput):
    next_variable_name: str
