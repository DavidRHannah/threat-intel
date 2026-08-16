from src.assets.store import create_asset, delete_asset, list_assets


def test_create_asset_merges_on_asset_key(driver):
    with driver.session() as s:
        a1 = s.execute_write(lambda tx: create_asset(tx, vendor="Cisco", product="IOS XE", version="17.3.1"))
        # Tag for automatic cleanup by conftest fixture
        s.run("MATCH (a:Asset {asset_key:$k}) SET a.test_fixture = true", k=a1["asset_key"]).consume()

        a2 = s.execute_write(lambda tx: create_asset(tx, vendor="cisco", product="ios xe", version="17.3.1"))
        # Tag for automatic cleanup by conftest fixture
        s.run("MATCH (a:Asset {asset_key:$k}) SET a.test_fixture = true", k=a2["asset_key"]).consume()

        assert a1["asset_key"] == a2["asset_key"]
        count = s.run("MATCH (a:Asset {asset_key:$k}) RETURN count(a) AS n", k=a1["asset_key"]).single()["n"]
        assert count == 1


def test_list_and_delete_asset(driver):
    with driver.session() as s:
        a = s.execute_write(lambda tx: create_asset(tx, vendor="acme", product="y", version="2.0", name="prod-1"))
        # Tag for automatic cleanup by conftest fixture
        s.run("MATCH (a:Asset {asset_key:$k}) SET a.test_fixture = true", k=a["asset_key"]).consume()

        assets = s.execute_read(list_assets)
        assert any(x["asset_key"] == a["asset_key"] and x["name"] == "prod-1" for x in assets)
        deleted = s.execute_write(lambda tx: delete_asset(tx, asset_key=a["asset_key"]))
        assert deleted is True
        assets_after = s.execute_read(list_assets)
        assert not any(x["asset_key"] == a["asset_key"] for x in assets_after)
        assert s.execute_write(lambda tx: delete_asset(tx, asset_key=a["asset_key"])) is False
