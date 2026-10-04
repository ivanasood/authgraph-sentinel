"""Scope-enforcing HTTP client.

This is the single choke point for all outbound traffic from the engine.
If a request targets a host that is not in config.allowed_hosts, it is
refused before leaving the process. Keeping this as the only HTTP path
means the scope guard cannot be bypassed by a detector module.
"""
from urllib.parse import urlparse

import httpx

from app.config import AssessmentConfig


class ScopeError(RuntimeError):
    """Raised when a request targets a host outside the authorized scope."""


class ScopedClient:
    def __init__(self, config: AssessmentConfig, timeout: float = 10.0):
        self.config = config
        self._client = httpx.Client(base_url=config.base_url, timeout=timeout)

    def _effective_host(self, url: str) -> str:
        parsed = urlparse(url)
        if parsed.netloc:                       # absolute URL
            return parsed.netloc
        return urlparse(self.config.base_url).netloc  # relative -> base_url host

    def _check(self, url: str) -> None:
        host = self._effective_host(url)
        if host not in self.config.allowed_hosts:
            raise ScopeError(
                f"Refusing request to '{host}' - not in authorized scope "
                f"{self.config.allowed_hosts}"
            )

    def request(self, method: str, url: str, **kwargs) -> httpx.Response:
        self._check(url)
        return self._client.request(method, url, **kwargs)

    def get(self, url: str, **kwargs) -> httpx.Response:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs) -> httpx.Response:
        return self.request("POST", url, **kwargs)

    def patch(self, url: str, **kwargs) -> httpx.Response:
        return self.request("PATCH", url, **kwargs)

    def delete(self, url: str, **kwargs) -> httpx.Response:
        return self.request("DELETE", url, **kwargs)

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "ScopedClient":
        return self

    def __exit__(self, *exc) -> None:
        self.close()
