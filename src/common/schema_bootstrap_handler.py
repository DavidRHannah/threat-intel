from src.common.neo4j_driver import get_driver
from src.common.schema_bootstrap import bootstrap_schema

_PHYSICAL_RESOURCE_ID = "crossroads-schema-bootstrap"


def handler(event: dict, context) -> dict:
    if event.get("RequestType") == "Delete":
        return {"PhysicalResourceId": _PHYSICAL_RESOURCE_ID}

    driver = get_driver()
    applied = bootstrap_schema(driver)
    return {
        "PhysicalResourceId": _PHYSICAL_RESOURCE_ID,
        "Data": {"AppliedConstraints": ",".join(applied)},
    }
