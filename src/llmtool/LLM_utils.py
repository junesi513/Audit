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


class LLM:
    """
    An online inference model using Gemini.
    """

    def __init__(
        self,
        online_model_name: str,
        logger: Logger,
        temperature: float = 0.0,
        system_role="You are a experienced programmer and good at understanding programs written in mainstream programming languages.",
    ) -> None:
        self.online_model_name = online_model_name
        self.temperature = temperature
        self.systemRole = system_role
        self.logger = logger
        self.gemini_model = genai.GenerativeModel(self.online_model_name)
        return

    def infer(
        self, message: str, is_measure_cost: bool = False
    ) -> Tuple[str, int, int]:
        self.logger.print_log(self.online_model_name, "is running")
        output = ""
        if "gemini" in self.online_model_name:
            output = self.infer_with_gemini(message)
        else:
            raise ValueError("Unsupported model name")

        input_token_cost = (
            0
            if not is_measure_cost
            else self.gemini_model.count_tokens(self.systemRole + "\n" + message).total_tokens
        )
        output_token_cost = (
            0 if not is_measure_cost else self.gemini_model.count_tokens(output).total_tokens
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
            message_with_role = self.systemRole + "\n" + message
            safety_settings = [
                {
                    "category": "HARM_CATEGORY_DANGEROUS",
                    "threshold": "BLOCK_NONE",
                },
                {
                    "category": "HARM_CATEGORY_HARASSMENT",
                    "threshold": "BLOCK_NONE",
                },
                {
                    "category": "HARM_CATEGORY_HATE_SPEECH",
                    "threshold": "BLOCK_NONE",
                },
                {
                    "category": "HARM_CATEGORY_SEXUALLY_EXPLICIT",
                    "threshold": "BLOCK_NONE",
                },
            ]
            response = self.gemini_model.generate_content(
                message_with_role,
                safety_settings=safety_settings,
                generation_config=genai.types.GenerationConfig(
                    temperature=self.temperature
                ),
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