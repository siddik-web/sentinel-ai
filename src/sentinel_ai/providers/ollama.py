"""Ollama Local LLM Provider implementation using native /api/chat API."""

import json
import urllib.request

from sentinel_ai.exceptions import SentinelError
from sentinel_ai.providers.base import LLMProvider, LLMResponse


class OllamaProvider(LLMProvider):
    """Provider for connecting to local Ollama instances (default http://localhost:11434)."""

    def __init__(
        self,
        model_name: str = "llama3",
        api_base: str = "http://localhost:11434",
    ):
        super().__init__(model_name=model_name)
        self.api_base = api_base.rstrip("/")

    def generate_completion(self, prompt: str, system_prompt: str | None = None) -> LLMResponse:
        url = f"{self.api_base}/api/chat"
        headers = {"Content-Type": "application/json"}

        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": self.model_name,
            "messages": messages,
            "format": "json",
            "stream": False,
        }

        try:
            req = urllib.request.Request(
                url, data=json.dumps(payload).encode("utf-8"), headers=headers, method="POST"
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                res_body = json.loads(resp.read().decode("utf-8"))

            content = res_body["message"]["content"]
            prompt_eval_count = res_body.get("prompt_eval_count", 0)
            eval_count = res_body.get("eval_count", 0)
            usage = {"prompt_tokens": prompt_eval_count, "completion_tokens": eval_count}

            structured_json = None
            try:
                structured_json = json.loads(content)
            except (json.JSONDecodeError, TypeError):
                structured_json = None

            return LLMResponse(
                content=content,
                model_name=self.model_name,
                structured_json=structured_json,
                token_usage=usage,
            )
        except Exception as e:
            raise SentinelError(f"Ollama Provider API request failed: {e!s}") from e
