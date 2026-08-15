#!/usr/bin/env python
"""Reconcile config/sources.yaml into DynamoDB + Neo4j (FR-DC-16).

`sync_sources` had no production caller: config/sources.yaml never reached AWS, so the
Sources table held only hand-seeded rows and no `Source` nodes existed at all.

DESTRUCTIVE: DynamoDB rows whose source_id is absent from the config are deleted, which
orphans the provenance of any Article already carrying that id. Always run --dry-run first.

Usage:
    python -m scripts.run_source_sync --dry-run
    python -m scripts.run_source_sync
    python -m scripts.run_source_sync --env prod --config config/sources.yaml
"""

import argparse
import os
import sys

import boto3
from neo4j import GraphDatabase

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.collection.source_config import plan_sync, sync_sources  # noqa: E402


def _ssm_param(ssm, env: str, name: str) -> str:
    return ssm.get_parameter(Name=f"/crossroads/{env}/{name}", WithDecryption=True)[
        "Parameter"
    ]["Value"]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env", default=os.environ.get("CROSSROADS_ENV", "dev"))
    parser.add_argument("--config", default="config/sources.yaml")
    parser.add_argument("--region", default=os.environ.get("AWS_REGION", "us-east-1"))
    parser.add_argument(
        "--dry-run", action="store_true", help="report the plan and write nothing"
    )
    args = parser.parse_args(argv)

    session = boto3.Session(region_name=args.region)
    table = session.resource("dynamodb").Table(f"crossroads-{args.env}-sources")

    plan = plan_sync(args.config, table)
    print(f"env={args.env} config={args.config} table={table.name}")
    print(f"  create : {plan.to_create or '-'}")
    print(f"  update : {plan.to_update or '-'}")
    print(f"  DELETE : {plan.to_delete or '-'}")

    if args.dry_run:
        print("\ndry-run: nothing written.")
        return 0

    if plan.to_delete:
        print(
            f"\nWARNING: {len(plan.to_delete)} row(s) will be deleted from DynamoDB. Any "
            "Article/IOC already carrying those source_ids loses its provenance lookup.",
            file=sys.stderr,
        )

    ssm = session.client("ssm")
    driver = GraphDatabase.driver(
        _ssm_param(ssm, args.env, "neo4j_uri"),
        auth=(
            _ssm_param(ssm, args.env, "neo4j_user"),
            _ssm_param(ssm, args.env, "neo4j_password"),
        ),
    )
    try:
        result = sync_sources(args.config, table, driver)
    finally:
        driver.close()

    print(
        f"\ncreated={result.created} updated={result.updated} "
        f"deactivated={result.deactivated} dynamodb_deleted={result.dynamodb_deleted}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
