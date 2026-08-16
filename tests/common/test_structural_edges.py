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


def test_resync_matches_publishes_node_write_only_for_newly_created_match(driver):
    cve_key = {"cve_id": "CVE-2026-9100"}
    with driver.session() as s:
        s.run("MERGE (c:CVE {cve_id: $cve_id})", **cve_key).consume()

        with patch("src.common.graph.structural_edges.publish_node_write") as mock_publish:
            s.execute_write(
                lambda tx: resync_matches(tx, cve_key=cve_key, matches=[_match("MC-9100")])
            )
            mock_publish.assert_called_once_with(
                label="CPEMatch",
                key={"match_criteria_id": "MC-9100"},
                changed_fields=["created"],
            )

        # Re-running with the SAME match is a re-confirmation, not a creation --
        # must NOT publish again.
        with patch("src.common.graph.structural_edges.publish_node_write") as mock_publish:
            s.execute_write(
                lambda tx: resync_matches(tx, cve_key=cve_key, matches=[_match("MC-9100")])
            )
            mock_publish.assert_not_called()

    with driver.session() as s:
        s.run("MATCH (c:CVE {cve_id: $cve_id}) DETACH DELETE c", **cve_key).consume()
        s.run(
            "MATCH (m:CPEMatch {match_criteria_id:'MC-9100'}) DETACH DELETE m"
        ).consume()
