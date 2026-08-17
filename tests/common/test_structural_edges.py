"""Final-review finding #1: `resync_matches` must be a PURE graph write.

It runs inside its caller's `execute_write` callback, so an SNS publish from here would
fire pre-commit and would bypass the caller's `publish=False` guard (the bulk NVD
backfill). The announcement now lives in `src/collection/rest/nvd.py`, post-commit --
see `tests/collection/rest/test_nvd.py::TestCpeMatchPublishing`.
"""

import sys
from unittest.mock import patch

from src.common.graph.structural_edges import resync_matches


def _match(match_id: str) -> dict:
    return {
        "match_criteria_id": match_id,
        "vendor": "acme",
        "product": "x",
        "version": "1.0.0",
        "version_start_including": None,
        "version_start_excluding": None,
        "version_end_including": None,
        "version_end_excluding": None,
        "vulnerable": True,
    }


def test_resync_matches_returns_created_ids_and_never_publishes(driver):
    cve_key = {"cve_id": "CVE-2026-9100"}
    with driver.session() as s:
        s.run("MERGE (c:CVE {cve_id: $cve_id})", **cve_key).consume()

        # Patch the publisher at its DEFINITION site, so any import path into it is
        # covered -- structural_edges no longer imports it at all, and this test would
        # go red the moment it (or anything it calls in-transaction) started to.
        with patch("src.common.graph.publish.publish_node_write") as mock_publish:
            result = s.execute_write(
                lambda tx: resync_matches(tx, cve_key=cve_key, matches=[_match("MC-9100")])
            )
            assert result["created"] == ["MC-9100"]
            mock_publish.assert_not_called()

        # Re-running with the SAME match is a re-confirmation, not a creation -- the
        # created list (which is what the caller publishes from) must be empty.
        with patch("src.common.graph.publish.publish_node_write") as mock_publish:
            result = s.execute_write(
                lambda tx: resync_matches(tx, cve_key=cve_key, matches=[_match("MC-9100")])
            )
            assert result["created"] == []
            mock_publish.assert_not_called()

    with driver.session() as s:
        s.run("MATCH (c:CVE {cve_id: $cve_id}) DETACH DELETE c", **cve_key).consume()
        s.run(
            "MATCH (m:CPEMatch {match_criteria_id:'MC-9100'}) DETACH DELETE m"
        ).consume()


def test_structural_edges_does_not_import_the_publisher():
    """Structural guard for the pre-commit half of the finding: the publish has to happen
    outside `session.execute_write`, and the only way to be sure `resync_matches` cannot
    publish pre-commit is that the module has no handle on the publisher at all."""
    module = sys.modules["src.common.graph.structural_edges"]
    assert not hasattr(module, "publish_node_write")
