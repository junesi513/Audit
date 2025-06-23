# Imports
from pathlib import Path
from typing import Tuple
import google.generativeai as genai
import signal
import sys
import time
import os
import concurrent.futures
from functools import partial
import threading

import json
from ui.logger import Logger
from openai import OpenAI
import anthropic


class LLM:
    """
    An online inference model using Gemini.
    """

    def __init__(
        self,
        model_name: str,
        temperature: float,
        system_role: str,
        logger: Logger
    ) -> None:
        self.model_name = model_name
        self.temperature = temperature
        self.system_role = system_role
        self.logger = logger
        self.token_num = 0

        if "gemini" in self.model_name:
            # As requested, hardcoding the API key directly in the code.
            api_key = "AIzaSyCWA58IOFNqypP0oENiOK5rvKApirD5P_w"
            genai.configure(api_key=api_key)
            self.model = genai.GenerativeModel(
                self.model_name,
                generation_config=genai.types.GenerationConfig(temperature=self.temperature),
                safety_settings=[ # Disable all safety settings
                    {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"},
                    {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE"},
                    {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE"},
                    {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"},
                ],
                system_instruction=self.system_role,
            )
        elif "gpt" in self.model_name:
            if not os.getenv("OPENAI_API_KEY"):
                raise ValueError("OPENAI_API_KEY environment variable not found.")
            self.openai_client = OpenAI()
            self.model = self.model_name
        elif "claude" in self.model_name:
            if not os.getenv("ANTHROPIC_API_KEY"):
                raise ValueError("ANTHROPIC_API_KEY environment variable not found.")
            self.anthropic_client = anthropic.Anthropic()
            self.model = self.model_name
        else:
            raise NotImplementedError(f"Model {self.model_name} is not supported.")

    def infer(
        self, message: str, is_measure_cost: bool = False
    ) -> Tuple[str, int, int]:
        self.logger.print_log(self.model_name, "is running")
        output = ""
        if "gemini" in self.model_name:
            output = self.infer_with_gemini(message)
        else:
            raise ValueError("Unsupported model name")

        input_token_cost = (
            0
            if not is_measure_cost
            else self.model.count_tokens(self.system_role + "\n" + message).total_tokens
        )
        output_token_cost = (
            0 if not is_measure_cost else self.model.count_tokens(output).total_tokens
        )
        return output, input_token_cost, output_token_cost

    def run_with_timeout(self, func, timeout):
        """Run a function with timeout that works in multiple threads"""
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(func)
            try:
                return future.result(timeout=timeout)
            except concurrent.futures.TimeoutError:
                ("Operation timed out")
                return ""
            except Exception as e:
                self.logger.print_log(f"Operation failed: {e}")
                return ""

    def infer_with_gemini(self, message: str) -> str:
        """Infer using the Gemini model from Google Generative AI"""
        def call_api():
            message_with_role = self.system_role + "\n" + message
            response = self.model.generate_content(
                message_with_role,
            )
            return response.text

        tryCnt = 0
        while tryCnt < 5:
            tryCnt += 1
            try:
                output = self.run_with_timeout(call_api, timeout=50)
                if output:
                    self.logger.print_log("Inference succeeded...")
                    return output
            except Exception as e:
                self.logger.print_log(f"API error: {e}")
            time.sleep(2)

        return ""