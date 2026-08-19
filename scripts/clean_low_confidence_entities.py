#!/usr/bin/env python
"""One-off removal of low-confidence LLM-derived entities (FR-EX-13).

Before FR-EX-13's confidence floor landed in extraction, every LLM-proposed
threat_actor/malware_family candidate reached the graph regardless of confidence
-- a 2026-08-19 quality review found ~40% of the ThreatActor/MalwareFamily
:Provisional nodes from one day's run were noise (vulnerable-software names,
VPN brands, CVE/GHSA IDs misclassified as malware). This applies the same
floor retroactively: finds and deletes the nodes the fixed extractor would
never have created.

A node is only deleted if it has no relationship besides MENTIONS -- one with
any other edge is skipped and reported, not force-deleted.

Usage:
    python -m scripts.clean_low_confidence_entities --dry-run
    python -m scripts.clean_low_confidence_entities
    python -m scripts.clean_low_confidence_entities --floor 0.6
"""

import argparse
import os
import sys

import boto3
from neo4j import GraphDatabase

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.nlp.resolution.cleanup import (  # noqa: E402
    delete_low_confidence_entities,
    find_removal_candidates,
)


def _ssm_param(ssm, env: str, name: str) -> str:
    return ssm.get_parameter(Name=f"/crossroads/{env}/{name}", WithDecryption=True)[
        "Parameter"
    ]["Value"]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env", default=os.environ.get("CROSSROADS_ENV", "dev"))
    parser.add_argument("--region", default=os.environ.get("AWS_REGION", "us-east-1"))
    parser.add_argument("--floor", type=float, default=0.5, help="confidence floor (default 0.5)")
    parser.add_argument(
        "--dry-run", action="store_true", help="report the candidate list and delete nothing"
    )
    args = parser.parse_args(argv)

    session = boto3.Session(region_name=args.region)
    ssm = session.client("ssm")
    driver = GraphDatabase.driver(
        _ssm_param(ssm, args.env, "neo4j_uri"),
        auth=(
            _ssm_param(ssm, args.env, "neo4j_user"),
            _ssm_param(ssm, args.env, "neo4j_password"),
        ),
    )

    try:
        candidates = find_removal_candidates(driver, floor=args.floor)
        print(f"env={args.env} floor={args.floor}")
        print(f"  candidates: {len(candidates)}")
        for c in sorted(candidates, key=lambda c: c["best_confidence"] or -1):
            other = set(c["rel_types"]) - {"MENTIONS"}
            flag = f" SKIP (has {other})" if other else ""
            print(f"    [{c['best_confidence']}] {c['merge_key']} ({c['labels']}){flag}")

        if args.dry_run:
            print("\ndry-run: nothing deleted.")
            return 0
        if not candidates:
            print("\nnothing to do.")
            return 0

        result = delete_low_confidence_entities(driver, floor=args.floor)
    finally:
        driver.close()

    print(f"\ndeleted={len(result.deleted)} skipped={len(result.skipped)}")
    if result.skipped:
        print(f"  skipped (had a non-MENTIONS edge, needs manual review): {result.skipped}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
