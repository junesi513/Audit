# Imports
from pathlib import Path
from typing import Tuple, Any, Dict, List
import google.generativeai as genai
import signal
import sys
import time
import os
import concurrent.futures
from functools import partial
import threading
from dataclasses import dataclass, field

import json
from src.ui.logger import Logger
from openai import OpenAI
import anthropic
import openai
import re

@dataclass
class LLMToolInput:
    function_id: str
    function_code: str

@dataclass
class LLMToolOutput:
    is_valid: bool
    output: Any = None
    error_message: str = None

class LLM:
    """
    An online inference model using Gemini.
    """

    def __init__(self, model_name='gemini-1.5-pro-latest', api_key=None, temperature=0.5, max_tokens=2048):
        self.model_name = model_name
        self.temperature = temperature
        self.max_tokens = max_tokens

        if 'gemini' in self.model_name.lower():
            self.api_key = api_key or os.getenv("GOOGLE_API_KEY")
            if not self.api_key:
                raise ValueError("GOOGLE_API_KEY environment variable not found or is empty.")
            genai.configure(api_key=self.api_key)
            self.model = genai.GenerativeModel(self.model_name)
        elif 'gpt' in self.model_name.lower():
            self.api_key = api_key or os.getenv("OPENAI_API_KEY")
            if not self.api_key:
                raise ValueError("OPENAI_API_KEY environment variable not found or is empty.")
            self.client = openai.OpenAI(api_key=self.api_key)
        else:
            raise ValueError(f"Unsupported model: {self.model_name}. Only Gemini and GPT models are supported.")

    def generate(self, prompt: str) -> str:
        try:
            if 'gemini' in self.model_name.lower():
                response = self.model.generate_content(
                    prompt,
                    generation_config=genai.types.GenerationConfig(
                        candidate_count=1,
                        max_output_tokens=self.max_tokens,
                        temperature=self.temperature,
                    ),
                    # Disabling all safety settings for this specific use case
                    safety_settings=[
                        {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"},
                        {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE"},
                        {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE"},
                        {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"},
                    ]
                )
                return response.text
            elif 'gpt' in self.model_name.lower():
                chat_completion = self.client.chat.completions.create(
                    messages=[{"role": "user", "content": prompt}],
                    model=self.model_name,
                )
                return chat_completion.choices[0].message.content
        except Exception as e:
            return f"An error occurred during LLM generation: {e}"

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

@dataclass
class LLMResponse:
    text: str
    
    def get_text(self):
        return self.text

class Prompt:
    def __init__(self, prompt_path: str):
        with open(prompt_path, 'r') as f:
            self.template_data = json.load(f)
        self.template = self.template_data.get("question_template", "")

    def get_string_with_inputs(self, inputs: Dict[str, str]) -> str:
        prompt_str = self.template
        for key, value in inputs.items():
            prompt_str = prompt_str.replace(f"<{key}>", value)
        return prompt_str

    def run(self, user_prompt: str) -> LLMResponse:
        response_text, _, _ = self.llm.infer(user_prompt, is_measure_cost=True)
        return LLMResponse(text=response_text)