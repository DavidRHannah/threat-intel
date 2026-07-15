from unittest.mock import MagicMock, patch

from src.common.schema_bootstrap_handler import handler


@patch("src.common.schema_bootstrap_handler.bootstrap_schema")
@patch("src.common.schema_bootstrap_handler.get_driver")
def test_create_event_runs_bootstrap_and_returns_applied_names(mock_get_driver, mock_bootstrap):
    mock_get_driver.return_value = MagicMock()
    mock_bootstrap.return_value = ["source_url_unique", "article_embedding_index"]

    result = handler({"RequestType": "Create"}, None)

    mock_bootstrap.assert_called_once_with(mock_get_driver.return_value)
    assert result["PhysicalResourceId"] == "crossroads-schema-bootstrap"
    assert result["Data"]["AppliedConstraints"] == "source_url_unique,article_embedding_index"


@patch("src.common.schema_bootstrap_handler.bootstrap_schema")
@patch("src.common.schema_bootstrap_handler.get_driver")
def test_delete_event_does_not_run_bootstrap(mock_get_driver, mock_bootstrap):
    result = handler({"RequestType": "Delete"}, None)

    mock_bootstrap.assert_not_called()
    assert result["PhysicalResourceId"] == "crossroads-schema-bootstrap"
