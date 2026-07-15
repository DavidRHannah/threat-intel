import functools
import os

import boto3


def _current_env() -> str:
    return os.environ.get("CROSSROADS_ENV", "local")


@functools.lru_cache(maxsize=None)
def get_config(name: str, default: str | None = None) -> str:
    env_var = f"CROSSROADS_{name.upper()}"
    if env_var in os.environ:
        return os.environ[env_var]

    env = _current_env()
    if env == "local":
        if default is not None:
            return default
        raise KeyError(f"{env_var} not set and no default provided (local env)")

    ssm = boto3.client("ssm", region_name="us-east-1")
    param_name = f"/crossroads/{env}/{name}"
    try:
        response = ssm.get_parameter(Name=param_name, WithDecryption=True)
    except ssm.exceptions.ParameterNotFound:
        if default is not None:
            return default
        raise KeyError(f"SSM parameter {param_name} not found and no default provided")
    return response["Parameter"]["Value"]
