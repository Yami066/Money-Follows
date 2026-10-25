"""One client for Groq and Gemini: both expose an OpenAI-compatible chat API with tool calling."""
import time
import httpx
from . import config

ENDPOINTS = {
    "groq": "https://api.groq.com/openai/v1/chat/completions",
    "gemini": "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions",
}


def _settings():
    if config.PROVIDER == "gemini":
        return ENDPOINTS["gemini"], config.GEMINI_API_KEY, config.GEMINI_MODEL
    return ENDPOINTS["groq"], config.GROQ_API_KEY, config.GROQ_MODEL


def available():
    return bool(_settings()[1])


def label():
    return f"{config.PROVIDER}:{_settings()[2]}"


def chat(messages, tools):
    url, key, model = _settings()
    body = {"model": model, "messages": messages, "tools": tools, "tool_choice": "auto", "temperature": 0.2}
    last = None
    for attempt in range(4):
        r = httpx.post(url, headers={"Authorization": f"Bearer {key}"}, json=body, timeout=60)
        if r.status_code == 429:
            time.sleep(min(20, float(r.headers.get("retry-after", 4 * (attempt + 1)))))
            continue
        if r.status_code == 400 and "tool_use_failed" in r.text:  # model produced a malformed tool call; retry
            last = r.text
            continue
        r.raise_for_status()
        return r.json()["choices"][0]["message"]
    raise RuntimeError(f"LLM call failed: {last or 'rate limited'}")
