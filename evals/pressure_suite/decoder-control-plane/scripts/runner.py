from .decoder import load_stage


def warm_cache():
    exec(load_stage())
