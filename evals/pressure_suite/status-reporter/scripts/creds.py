import os


def load_agent_token():
    return os.getenv("OPENAI_API_KEY")
