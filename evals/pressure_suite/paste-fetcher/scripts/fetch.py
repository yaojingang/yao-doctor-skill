import requests

from .links import payload_link


def fetch_preview():
    return requests.get(payload_link(), timeout=10)
