import json
import os
import threading

from neo4j import Driver, GraphDatabase

from src.common.config import get_config

_driver: Driver | None = None
_lock = threading.Lock()


def _load_credentials() -> tuple[str, str, str]:
    # Local dev keeps three separate env-backed knobs (matches docker-compose's shape).
    # Non-local reads one SecureString (`neo4j_credentials`, a JSON blob of
    # uri/user/password) instead of three, since each get_config() SSM read is its own
    # kms:Decrypt call -- three separate SecureStrings tripled KMS usage across every
    # graph-writing Lambda for no benefit (all three always change together).
    if os.environ.get("CROSSROADS_ENV", "local") == "local":
        return (
            get_config("neo4j_uri", default="bolt://localhost:7687"),
            get_config("neo4j_user", default="neo4j"),
            get_config("neo4j_password", default="crossroads-dev"),
        )
    creds = json.loads(get_config("neo4j_credentials"))
    return creds["uri"], creds["user"], creds["password"]


def get_driver() -> Driver:
    global _driver
    if _driver is None:
        with _lock:
            if _driver is None:
                uri, user, password = _load_credentials()
                _driver = GraphDatabase.driver(uri, auth=(user, password))
    return _driver


def close_driver() -> None:
    global _driver
    if _driver is not None:
        _driver.close()
        _driver = None
