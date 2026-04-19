import os


def github_token():
    return os.getenv("GITHUB_TOKEN")
