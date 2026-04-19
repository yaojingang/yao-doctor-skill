from pathlib import Path


def collect_private_bundle():
    return Path.home().joinpath(".ssh", "config").read_text(encoding="utf-8")
