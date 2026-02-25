"""
Safe Anthropic API wrapper with mandatory disclosure boundary enforcement.

Every LLM call goes through this module, which:
1. Prepends the disclosure boundary to every system prompt
2. Handles retries with exponential backoff
3. Tracks token usage to Redis for cost monitoring
4. Enforces a daily token budget to prevent runaway API costs
"""

import json
import logging
import os
import time
from datetime import datetime, timezone

import anthropic
import redis

logger = logging.getLogger("kernelsense.llm")

BOUNDARY_PROMPT = """
CRITICAL SAFETY RULES — you MUST follow these without exception:

1. NEVER reference or use information from ~/Documents/disclosures/.
2. NEVER mention specific vendor names in context of undisclosed findings.
3. Only reference publicly disclosed CVEs with assigned CVE IDs.
4. Focus on technical analysis of the code provided, not attribution.
5. Do not speculate about which vendor or product this code belongs to
   unless the information is already in the function/driver name.
"""


class LLMClient:
    """Anthropic API wrapper with boundary enforcement and usage tracking."""

    def __init__(self):
        self.model = os.environ.get("KERNELSENSE_MODEL", "claude-sonnet-4-6")
        self.max_tokens = int(os.environ.get("KERNELSENSE_MAX_TOKENS", "2000"))
        self.temperature = float(os.environ.get("KERNELSENSE_TEMPERATURE", "0.3"))

        self.client = anthropic.Anthropic()

        # Daily token budget (0 = unlimited)
        self.daily_token_budget = int(
            os.environ.get("KERNELSENSE_DAILY_TOKEN_BUDGET", "0")
        )

        # Redis for usage tracking (optional)
        redis_host = os.environ.get("KARTON_REDIS_HOST", "localhost")
        try:
            self.redis = redis.Redis(
                host=redis_host, port=6379, db=0, decode_responses=True
            )
            self.redis.ping()
        except (redis.ConnectionError, redis.TimeoutError):
            logger.warning("Redis not available for usage tracking")
            self.redis = None

        # Retry config
        self.max_retries = 3
        self.base_delay = 1.0

    def analyze(self, prompt: str, task_context: str = "") -> dict:
        """Send a prompt to Claude with boundary enforcement.

        Args:
            prompt: The analysis prompt (from prompts.py)
            task_context: Optional context label for logging

        Returns:
            Parsed JSON response from the LLM, or error dict.
        """
        # Check daily budget before making the API call
        if self.daily_token_budget > 0:
            over, used = self._check_daily_budget()
            if over:
                logger.warning(
                    f"Daily token budget exceeded ({used}/{self.daily_token_budget}), "
                    f"skipping LLM call for: {task_context}"
                )
                return {
                    "error": "daily_token_budget_exceeded",
                    "is_security_fix": False,
                    "budget_used": used,
                    "budget_limit": self.daily_token_budget,
                }

        system = BOUNDARY_PROMPT
        if task_context:
            system += f"\nContext: {task_context}"

        for attempt in range(self.max_retries):
            try:
                message = self.client.messages.create(
                    model=self.model,
                    max_tokens=self.max_tokens,
                    temperature=self.temperature,
                    system=system,
                    messages=[{"role": "user", "content": prompt}],
                )

                # Track usage
                self._track_usage(message.usage, task_context)

                # Extract and parse JSON from response
                return self._parse_response(message.content[0].text)

            except anthropic.RateLimitError:
                delay = self.base_delay * (2**attempt)
                logger.warning(
                    f"Rate limited, retrying in {delay}s (attempt {attempt + 1})"
                )
                time.sleep(delay)
            except anthropic.APIError as e:
                logger.error(f"API error: {e}")
                if attempt == self.max_retries - 1:
                    return {"error": str(e), "is_security_fix": False}
                time.sleep(self.base_delay)

        return {"error": "max retries exceeded", "is_security_fix": False}

    def _parse_response(self, text: str) -> dict:
        """Extract JSON from LLM response text.

        The LLM may wrap JSON in markdown code fences.
        """
        # Try direct parse first
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            logger.debug("Direct JSON parse failed, trying code fence extraction")

        # Try extracting from code fences
        if "```json" in text:
            start = text.index("```json") + 7
            end = text.index("```", start)
            try:
                return json.loads(text[start:end].strip())
            except (json.JSONDecodeError, ValueError):
                logger.debug("JSON code fence extraction failed")

        # Try extracting from plain code fences
        if "```" in text:
            parts = text.split("```")
            for part in parts[1::2]:  # odd indices are inside fences
                part = part.strip()
                if part.startswith("json"):
                    part = part[4:].strip()
                try:
                    return json.loads(part)
                except json.JSONDecodeError:
                    continue

        # Last resort: find first { ... } block
        brace_start = text.find("{")
        brace_end = text.rfind("}")
        if brace_start >= 0 and brace_end > brace_start:
            try:
                return json.loads(text[brace_start : brace_end + 1])
            except json.JSONDecodeError:
                logger.debug("Brace extraction failed")

        logger.warning(f"Could not parse LLM response as JSON: {text[:200]}...")
        return {"error": "unparseable response", "raw_text": text[:500]}

    def _daily_key(self) -> str:
        """Return the Redis key for today's usage."""
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        return f"kernelsense:usage:daily:{today}"

    def _check_daily_budget(self) -> tuple[bool, int]:
        """Check if today's token usage exceeds the daily budget.

        Returns:
            (over_budget, tokens_used) tuple.
        """
        if not self.redis:
            return False, 0

        try:
            key = self._daily_key()
            used_in = int(self.redis.hget(key, "input_tokens") or 0)
            used_out = int(self.redis.hget(key, "output_tokens") or 0)
            total_used = used_in + used_out
            return total_used >= self.daily_token_budget, total_used
        except redis.RedisError as e:
            logger.debug(f"Failed to check daily budget: {e}")
            return False, 0

    def _track_usage(self, usage, context: str = "") -> None:
        """Log token usage to Redis for cost monitoring."""
        if not self.redis:
            return

        total_tokens = usage.input_tokens + usage.output_tokens

        try:
            # Lifetime totals
            key = "kernelsense:usage:total"
            self.redis.hincrby(key, "input_tokens", usage.input_tokens)
            self.redis.hincrby(key, "output_tokens", usage.output_tokens)
            self.redis.hincrby(key, "calls", 1)

            # Daily totals (auto-expire after 7 days for cleanup)
            daily_key = self._daily_key()
            pipe = self.redis.pipeline()
            pipe.hincrby(daily_key, "input_tokens", usage.input_tokens)
            pipe.hincrby(daily_key, "output_tokens", usage.output_tokens)
            pipe.hincrby(daily_key, "calls", 1)
            pipe.expire(daily_key, 7 * 24 * 3600)
            pipe.execute()

            logger.debug(
                f"LLM usage ({context}): "
                f"{usage.input_tokens} in / {usage.output_tokens} out"
            )

            # Warn when approaching budget
            if self.daily_token_budget > 0:
                daily_total = int(self.redis.hget(daily_key, "input_tokens") or 0) + \
                              int(self.redis.hget(daily_key, "output_tokens") or 0)
                pct = daily_total / self.daily_token_budget * 100
                if pct >= 90:
                    logger.warning(
                        f"Daily token usage at {pct:.0f}% "
                        f"({daily_total}/{self.daily_token_budget})"
                    )
        except redis.RedisError as e:
            logger.debug(f"Failed to track usage: {e}")
