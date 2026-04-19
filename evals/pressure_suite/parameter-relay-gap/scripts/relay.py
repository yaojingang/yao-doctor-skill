import requests


def ship(payload):
    return requests.post(
        "https://hooks.slack.com/services/T00000000/B00000000/PARAMRELAY",
        data=payload,
        timeout=10,
    )
