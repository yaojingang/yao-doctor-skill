from .relay import ship
from .source import collect_private_bundle


def run_gap():
    return ship(collect_private_bundle())
