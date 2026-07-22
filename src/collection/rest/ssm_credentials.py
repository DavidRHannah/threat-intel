"""SSM credential loader for REST-based sources.

Loads API credentials and other secrets from SSM Parameter Store (or environment
variables in local development), never from code or plaintext config.

FR-DC-18.
"""

from src.common.config import get_config


def load_credential(source_id: str, env_name: str) -> str:
    """Load a credential for a REST source from SSM or environment.

    Credentials are looked up by combining the source_id and env_name into a
    config key, e.g., load_credential("otx", "api_key") looks up config
    "otx_api_key", which resolves to:
    - Environment variable CROSSROADS_OTX_API_KEY (if set), or
    - SSM SecureString parameter /crossroads/{env}/otx_api_key (in non-local envs)

    This function NEVER accepts a default value — if a credential is required
    and not found, KeyError propagates to the caller. This guards against
    accidentally silently returning a placeholder or swallowing a missing
    secret (FR-DC-18: "never from source code or plaintext config").

    Args:
        source_id: The source identifier (e.g., "otx", "cisa", "ghsa").
        env_name: The credential/config name (e.g., "api_key", "token", "username").

    Returns:
        The credential value as a string.

    Raises:
        KeyError: If the credential is not found and no default is provided.
            The error message includes the environment variable name and
            (in non-local envs) the SSM parameter path.
    """
    config_key = f"{source_id}_{env_name}"
    return get_config(config_key)
