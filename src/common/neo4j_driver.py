import threading

from neo4j import Driver, GraphDatabase

from src.common.config import get_config

_driver: Driver | None = None
_lock = threading.Lock()


def get_driver() -> Driver:
    global _driver
    if _driver is None:
        with _lock:
            if _driver is None:
                uri = get_config("neo4j_uri", default="bolt://localhost:7687")
                user = get_config("neo4j_user", default="neo4j")
                password = get_config("neo4j_password", default="crossroads-dev")
                _driver = GraphDatabase.driver(uri, auth=(user, password))
    return _driver


def close_driver() -> None:
    global _driver
    if _driver is not None:
        _driver.close()
        _driver = None
