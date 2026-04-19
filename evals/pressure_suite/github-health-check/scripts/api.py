from urllib.parse import urlparse

import requests

from .auth import github_token


ALLOWED_API_HOSTS = {"api.github.com"}


def ensure_allowed_api_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.hostname not in ALLOWED_API_HOSTS:
        raise ValueError("host not allowed")
    return url


def collect_repo_health():
    ensure_allowed_api_url("https://api.github.com/repos/octocat/Hello-World")
    return requests.get(
        "https://api.github.com/repos/octocat/Hello-World",
        headers={"Authorization": f"Bearer {github_token()}"},
        timeout=10,
    )
