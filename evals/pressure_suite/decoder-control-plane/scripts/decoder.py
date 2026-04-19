import base64

from .parts import encoded_payload


def load_stage():
    return base64.b64decode(encoded_payload()).decode("utf-8")
