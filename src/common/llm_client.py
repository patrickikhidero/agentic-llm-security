"""
llm_client.py
─────────────
Thin, provider-agnostic chat-completion client.

The experimental pipeline uses Groq's OpenAI-compatible endpoint to run
open-weight models (free tier, no vendor lock-in; currently gpt-oss-20b) instead of a
proprietary hosted model. Groq's API is wire-compatible with the OpenAI
client, so the same `openai` SDK is reused with a different base_url.

Includes retry-with-backoff for the free tier's rate limits (HTTP 429), and
a proactive token-bucket limiter — this account's free tier caps at 8,000
tokens/minute account-wide (observed via the x-ratelimit-* response headers,
same limit across every model tried), which a multi-step agent blows
through quickly since each step resends the growing conversation history.
Waiting proactively avoids repeatedly hitting 429 and burning through
retries only to have some trials fail outright once retries are exhausted.
"""

import json
import logging
import os
import threading
import time

from openai import APIStatusError, OpenAI

logger = logging.getLogger(__name__)

GROQ_BASE_URL = "https://api.groq.com/openai/v1"
DEFAULT_MODEL = "openai/gpt-oss-20b"

_client: OpenAI | None = None


class DailyQuotaExhausted(Exception):
    """Raised immediately (no retries) when a provider reports the request
    was rejected for a per-day token quota, not a per-minute rate limit —
    retrying within the same process cannot help, since the quota won't
    reset for hours. Callers should checkpoint progress and stop."""


def _is_daily_quota_error(exc: APIStatusError) -> bool:
    body = str(getattr(exc, "body", "") or exc)
    return exc.status_code == 429 and ("tokens per day" in body or "(TPD)" in body)


def get_client() -> OpenAI:
    global _client
    if _client is None:
        api_key = os.getenv("GROQ_API_KEY")
        if not api_key:
            raise RuntimeError(
                "GROQ_API_KEY is not set. Get a free key at https://console.groq.com "
                "and add it to .env"
            )
        _client = OpenAI(api_key=api_key, base_url=GROQ_BASE_URL)
    return _client


class _TokenRateLimiter:
    """Sliding 60s-window limiter. Estimates a request's cost before sending
    and blocks until the trailing window has headroom, then reconciles the
    estimate against the real usage.total_tokens once the response is in."""

    def __init__(self, tpm_budget: int = 8000, safety_margin: float = 0.85) -> None:
        self.budget = tpm_budget * safety_margin
        self._window: list[tuple[float, int]] = []
        self._lock = threading.Lock()

    def _prune(self, now: float) -> int:
        cutoff = now - 60
        self._window = [(t, n) for t, n in self._window if t > cutoff]
        return sum(n for _, n in self._window)

    def reserve(self, estimated_tokens: int) -> None:
        while True:
            with self._lock:
                now = time.time()
                used = self._prune(now)
                if used + estimated_tokens <= self.budget or not self._window:
                    self._window.append((now, estimated_tokens))
                    return
                wait = max(1.0, 61 - (now - self._window[0][0]))
            logger.info(f"Rate limiter: pausing ~{wait:.0f}s to stay under the account's token/min budget")
            time.sleep(wait)

    def reconcile(self, estimated_tokens: int, actual_tokens: int) -> None:
        delta = actual_tokens - estimated_tokens
        if delta:
            with self._lock:
                self._window.append((time.time(), delta))


_rate_limiter = _TokenRateLimiter()


def _estimate_tokens(messages: list[dict], max_tokens: int) -> int:
    prompt_chars = sum(len(json.dumps(m)) for m in messages)
    # reasoning_effort="low" keeps actual completions well under max_tokens
    # in practice; 350 is a conservative real-world estimate, not the cap.
    return prompt_chars // 4 + 350


def chat_completion_with_tools(messages: list[dict], tools: list[dict],
                                model: str = DEFAULT_MODEL,
                                temperature: float = 0.0, max_tokens: int = 1500,
                                max_retries: int = 5):
    """Native function-calling variant. gpt-oss models are trained for real
    tool-calling and misbehave (hallucinating an undeclared built-in tool)
    when instead asked to emit a hand-rolled 'respond with this JSON shape'
    protocol in plain content — so tool-bearing steps use the real `tools`
    API surface and this returns the raw response message (either
    `.tool_calls` or `.content` is populated, per the OpenAI SDK contract),
    not just a content string.
    """
    client = get_client()
    kwargs: dict = {
        "model": model,
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_tokens,
        "tools": tools,
        "tool_choice": "auto",
        "extra_body": {"reasoning_effort": "low"},
    }

    delay = 2.0
    last_exc: Exception | None = None
    for attempt in range(1, max_retries + 1):
        estimate = _estimate_tokens(messages, max_tokens)
        _rate_limiter.reserve(estimate)
        try:
            response = client.chat.completions.create(**kwargs)
            if response.usage:
                _rate_limiter.reconcile(estimate, response.usage.total_tokens)
            return response.choices[0].message
        except APIStatusError as exc:
            if _is_daily_quota_error(exc):
                raise DailyQuotaExhausted(str(exc)) from exc
            last_exc = exc
            if exc.status_code == 429 or exc.status_code >= 500:
                logger.warning(
                    f"LLM call failed (status={exc.status_code}), "
                    f"retry {attempt}/{max_retries} in {delay:.1f}s"
                )
            else:
                raise
        except Exception as exc:  # noqa: BLE001 - network hiccups, retry
            last_exc = exc
            logger.warning(f"LLM call error: {exc}, retry {attempt}/{max_retries} in {delay:.1f}s")

        time.sleep(delay)
        delay = min(delay * 2, 30)

    raise RuntimeError(f"LLM call failed after {max_retries} retries: {last_exc}")


def chat_completion(messages: list[dict], model: str = DEFAULT_MODEL,
                     temperature: float = 0.0, max_tokens: int = 800,
                     json_mode: bool = False, max_retries: int = 5) -> str:
    """Call the chat completion endpoint with retry/backoff on rate limits."""
    client = get_client()
    kwargs: dict = {
        "model": model,
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_tokens,
        # gpt-oss models emit hidden chain-of-thought reasoning tokens that
        # otherwise eat into max_tokens and can truncate the actual JSON
        # response before it's ever produced; "low" keeps that budget small.
        "extra_body": {"reasoning_effort": "low"},
    }
    if json_mode:
        kwargs["response_format"] = {"type": "json_object"}

    delay = 2.0
    last_exc: Exception | None = None
    for attempt in range(1, max_retries + 1):
        estimate = _estimate_tokens(messages, max_tokens)
        _rate_limiter.reserve(estimate)
        try:
            response = client.chat.completions.create(**kwargs)
            if response.usage:
                _rate_limiter.reconcile(estimate, response.usage.total_tokens)
            content = response.choices[0].message.content or ""
            if content.strip():
                return content
            # gpt-oss's reasoning-token budget occasionally consumes the
            # entire completion with none left for visible content — the
            # call succeeds (HTTP 200) but content is empty. Not an
            # exception, so it wouldn't otherwise be retried.
            last_exc = RuntimeError("Model returned empty content")
            logger.warning(f"Empty completion content, retry {attempt}/{max_retries} in {delay:.1f}s")
        except APIStatusError as exc:
            if _is_daily_quota_error(exc):
                raise DailyQuotaExhausted(str(exc)) from exc
            last_exc = exc
            if exc.status_code == 400 and "json_validate_failed" in str(getattr(exc, "body", "") or exc):
                # Deterministic for this exact request — retrying it
                # unchanged reproduces the same failure every time, so drop
                # strict JSON-mode instead of just retrying identically.
                if "response_format" in kwargs:
                    logger.warning("Strict JSON-mode generation failed; dropping response_format")
                    kwargs = {k: v for k, v in kwargs.items() if k != "response_format"}
                else:
                    logger.warning(f"Generation failed again without JSON-mode, "
                                    f"retry {attempt}/{max_retries} in {delay:.1f}s")
            elif exc.status_code == 429 or exc.status_code >= 500:
                logger.warning(
                    f"LLM call failed (status={exc.status_code}), "
                    f"retry {attempt}/{max_retries} in {delay:.1f}s"
                )
            else:
                raise
        except Exception as exc:  # noqa: BLE001 - network hiccups, retry
            last_exc = exc
            logger.warning(f"LLM call error: {exc}, retry {attempt}/{max_retries} in {delay:.1f}s")

        time.sleep(delay)
        delay = min(delay * 2, 30)

    raise RuntimeError(f"LLM call failed after {max_retries} retries: {last_exc}")
