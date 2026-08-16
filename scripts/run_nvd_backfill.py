#!/usr/bin/env python
"""Backfill NVD enrichment onto CVE nodes no NVD read has ever touched (FR-DC-22).

CISA KEV/GHSA/OTX MERGE bare `cve_id` stubs, and the scheduled delta poll only revisits
CVEs NVD modified inside its poll window — so a stub for an older CVE is never enriched
by anything. This is the catch-up pass: one NVD request per CVE, populating description,
CVSS, CWE mappings and `affected_products` (CPE).

Safe to interrupt and re-run. The work list is derived from the graph on every run
(CVEs with no `last_modified_date`), so a re-run resumes where the last one stopped and
a finished backfill is a no-op. CVEs NVD has no record of are stamped `nvd_not_found_at`
and skipped by later runs.

Rate limits are NVD's: 5 requests/30s keyless, 50/30s with an API key at
`/crossroads/{env}/nvd_api_key`. Over ~1.7k CVEs that is roughly 3 hours vs 20 minutes.

Usage:
    python -m scripts.run_nvd_backfill --dry-run
    python -m scripts.run_nvd_backfill --limit 25      # a small real run first
    python -m scripts.run_nvd_backfill
"""

import argparse
import os
import sys
import time

import boto3
import httpx
from neo4j import GraphDatabase

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.collection.rest.nvd_backfill import (  # noqa: E402
    backfill,
    find_unenriched_cve_ids,
    rate_limiter_for,
)


def _ssm_param(ssm, env: str, name: str) -> str:
    return ssm.get_parameter(Name=f"/crossroads/{env}/{name}", WithDecryption=True)[
        "Parameter"
    ]["Value"]


def _optional_ssm_param(ssm, env: str, name: str) -> str | None:
    try:
        return _ssm_param(ssm, env, name)
    except ssm.exceptions.ParameterNotFound:
        return None


def _format_eta(seconds: float) -> str:
    minutes, secs = divmod(int(seconds), 60)
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h{minutes:02d}m" if hours else f"{minutes}m{secs:02d}s"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env", default=os.environ.get("CROSSROADS_ENV", "dev"))
    parser.add_argument("--region", default=os.environ.get("AWS_REGION", "us-east-1"))
    parser.add_argument("--limit", type=int, default=None, help="stop after N CVEs")
    parser.add_argument(
        "--dry-run", action="store_true", help="report the work list and write nothing"
    )
    parser.add_argument(
        "--publish",
        action="store_true",
        help=(
            "announce each CVSS change on graph-writes. Off by default: a bulk backfill "
            "would fan thousands of messages out to L4's per-message Lambda, and the "
            "daily scoring sweep picks these CVEs up anyway."
        ),
    )
    args = parser.parse_args(argv)

    session = boto3.Session(region_name=args.region)
    ssm = session.client("ssm")

    api_key = _optional_ssm_param(ssm, args.env, "nvd_api_key")
    if api_key is None:
        print(
            f"WARNING: no /crossroads/{args.env}/nvd_api_key — running at the keyless "
            "rate limit (5 req/30s), roughly 10x slower.",
            file=sys.stderr,
        )

    driver = GraphDatabase.driver(
        _ssm_param(ssm, args.env, "neo4j_uri"),
        auth=(
            _ssm_param(ssm, args.env, "neo4j_user"),
            _ssm_param(ssm, args.env, "neo4j_password"),
        ),
    )

    try:
        pending = find_unenriched_cve_ids(driver, limit=args.limit)
        limiter = rate_limiter_for(has_api_key=api_key is not None)
        per_request = limiter.seconds_per_request
        print(f"env={args.env}  api_key={'yes' if api_key else 'no'}")
        print(f"  CVEs needing enrichment : {len(pending)}")
        print(f"  first few               : {', '.join(pending[:5]) or '-'}")
        print(f"  estimated runtime       : {_format_eta(len(pending) * per_request)}")

        if args.dry_run:
            print("\ndry-run: nothing written.")
            return 0
        if not pending:
            print("\nnothing to do.")
            return 0

        started = time.monotonic()

        def progress(index: int, total: int, cve_id: str) -> None:
            # Every request costs real wall-clock time against the rate limit, so print
            # often enough that an unattended multi-hour run is visibly alive.
            if index % 25 == 0 or index == total:
                elapsed = time.monotonic() - started
                remaining = (elapsed / index) * (total - index)
                print(
                    f"  [{index}/{total}] {cve_id}  eta {_format_eta(remaining)}",
                    flush=True,
                )

        # `headers=` rather than a query param: NVD takes the key as an `apiKey` HEADER,
        # and this keeps it out of any URL that might be logged. Passing it on the client
        # also means no change to the normalizer's `get(url, params)` seam.
        headers = {"apiKey": api_key} if api_key else {}
        with httpx.Client(headers=headers, timeout=30.0) as client:
            result = backfill(
                driver,
                client,
                rate_limiter=limiter,
                limit=args.limit,
                publish=args.publish,
                on_progress=progress,
            )
    finally:
        driver.close()

    print(
        f"\nattempted={result.attempted} enriched={result.enriched} "
        f"not_found={result.not_found}"
    )
    if result.not_found:
        print(
            f"  {result.not_found} CVE(s) had no NVD record; stamped nvd_not_found_at "
            "and excluded from future runs."
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
