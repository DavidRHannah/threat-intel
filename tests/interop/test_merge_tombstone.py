from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from src.interop.merge_tombstone import handle_node_merge


@patch("boto3.resource")
def test_handle_node_merge_writes_tombstone(mock_boto_resource, monkeypatch):
    monkeypatch.setenv("CROSSROADS_REVOKED_STIX_IDS_TABLE_NAME", "revoked-stix-ids")
    mock_table = MagicMock()
    mock_boto_resource.return_value.Table.return_value = mock_table

    message = {
        "label": "ThreatActor",
        "old_key": {"merge_key": "scattered spider"},
        "new_key": {"merge_key": "g1015"},
    }
    result = handle_node_merge(message, datetime(2026, 8, 11, 12, 0, tzinfo=timezone.utc))

    assert result is True
    put_item_call = mock_table.put_item.call_args
    item = put_item_call.kwargs["Item"]
    assert item["stix_id"].startswith("intrusion-set--")
    assert item["revoked_at"] == "2026-08-11T12:00:00+00:00"
    assert item["reason"] == "reconciled"


def test_handle_node_merge_missing_keys_returns_false():
    result = handle_node_merge({"label": "ThreatActor"}, datetime.now(timezone.utc))
    assert result is False
