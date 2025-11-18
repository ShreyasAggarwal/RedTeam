# models/client.py
import time
import json
import os
import hashlib
from datetime import datetime

from langchain_openai import ChatOpenAI
from langchain_google_genai import ChatGoogleGenerativeAI

class ModelClient:
    def __init__(self, provider="mock", api_key=None, sanitize=False,
                 enable_rate_limiting=False, enable_audit_logging=False,
                 user="system"):
        self.provider = provider
        self.api_key = api_key
        self.sanitize = sanitize
        self.enable_rate_limiting = enable_rate_limiting
        self.enable_audit_logging = enable_audit_logging
        self.user = user
        os.makedirs("data", exist_ok=True)
        self.log_path = os.path.join("data", "model_calls.log")

        # Initialize security features if enabled
        self.rate_limiter = None
        self.audit_logger = None

        if enable_rate_limiting:
            try:
                from security.rate_limiter import get_model_rate_limiter
                self.rate_limiter = get_model_rate_limiter()
            except ImportError:
                print("Warning: Rate limiting requested but security module not found")

        if enable_audit_logging:
            try:
                from security.audit_logger import get_audit_logger
                self.audit_logger = get_audit_logger()
            except ImportError:
                print("Warning: Audit logging requested but security module not found")

    def _log(self, attack_id, prompt, meta=None):
        entry = {
            "ts": datetime.utcnow().isoformat()+"Z",
            "attack_id": attack_id,
            "prompt_trunc": prompt[:400],
            "meta": meta or {}
        }
        with open(self.log_path, "a", encoding="utf8") as f:
            f.write(json.dumps(entry) + "\n")

    def _get_llm(self, temperature, max_tokens):
        models = {
            "openai": lambda: ChatOpenAI(
                model="gpt-4o-mini",
                temperature=1.0,
                max_tokens=max_tokens,
                api_key=self.api_key
            ),
            "gemini": lambda: ChatGoogleGenerativeAI(
                model='gemini-2.5-flash',
                temperature=temperature,
                max_tokens=max_tokens,
                google_api_key=self.api_key
            )
            # TODO: Add additional llms here
        }
        model = models.get(self.provider)
        if not model:
            raise ValueError(f"Unkown or unsupported provider: {self.provider}")
        return model

    def sanitize_input(self, prompt):
        if not self.sanitize:
            return prompt, {}
        # simple sanitization: remove 'ignore previous' phrases
        replaced = prompt.replace("Ignore previous instructions", "[sanitized]")
        meta = {"sanitized": True}
        return replaced, meta

    def query(self, attack_id, prompt, max_tokens=200, temperature=1.0, **kwargs):
        # Rate limiting check
        if self.rate_limiter:
            if not self.rate_limiter.wait_if_needed(self.provider, max_wait=30.0):
                raise RuntimeError(f"Rate limit exceeded for {self.provider}")

        # Hash prompt for audit logging (don't log actual prompt for security)
        prompt_hash = hashlib.sha256(prompt.encode('utf-8')).hexdigest()[:16]

        if self.sanitize:
            prompt, smeta = self.sanitize_input(prompt)
        else:
            smeta = {}

        if self.provider == "mock":
            from models.mock import mock_response_for_attack
            resp = mock_response_for_attack(attack_id, prompt)
            meta = {"mock": True}
            self._log(attack_id, prompt, meta)

            # Audit log
            if self.audit_logger:
                self.audit_logger.log_model_query(
                    user=self.user,
                    model=self.provider,
                    prompt_hash=prompt_hash,
                    response_length=len(resp),
                    details={"attack_id": attack_id}
                )

            return {"text": resp, "meta": meta}

        if not self.api_key:
            raise RuntimeError(f"{self.provider} provider requested but no API key provided")

        llm = self._get_llm(temperature=temperature, max_tokens=max_tokens)
        response = llm.invoke(prompt)
        text = response.content
        meta = {"mock": False, "provider": self.provider}
        self._log(attack_id, prompt, meta)

        # Audit log
        if self.audit_logger:
            self.audit_logger.log_model_query(
                user=self.user,
                model=self.provider,
                prompt_hash=prompt_hash,
                response_length=len(text),
                details={"attack_id": attack_id}
            )

        return {"text": text, "meta": meta}