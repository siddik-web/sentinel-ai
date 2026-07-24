"""OpenAI-compatible LLM Provider implementation using standard library HTTP."""

import json
import urllib.request

from sentinel_ai.exceptions import SentinelError
from sentinel_ai.providers.base import LLMProvider, LLMResponse


class OpenAICompatibleProvider(LLMProvider):
    """Provider connecting to OpenAI, Azure OpenAI, vLLM, or Ollama API endpoints."""

    def __init__(
        self,
        api_key: str = "mock-key",
        api_base: str = "https://api.openai.com/v1",
        model_name: str = "gpt-4o-mini",
    ):
        super().__init__(model_name=model_name)
        self.api_key = api_key
        self.api_base = api_base.rstrip("/")

    def generate_completion(self, prompt: str, system_prompt: str | None = None) -> LLMResponse:
        url = f"{self.api_base}/chat/completions"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
        }

        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": self.model_name,
            "messages": messages,
            "response_format": {"type": "json_object"},
            "temperature": 0.0,
        }

        try:
            req = urllib.request.Request(
                url, data=json.dumps(payload).encode("utf-8"), headers=headers, method="POST"
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                res_body = json.loads(resp.read().decode("utf-8"))

            content = res_body["choices"][0]["message"]["content"]
            usage = res_body.get("usage", {"prompt_tokens": 0, "completion_tokens": 0})

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
            raise SentinelError(f"LLM Provider API request failed: {e!s}") from e
