from neo4j import Driver

from src.common.config import get_config

DEFAULT_VECTOR_DIMENSIONS = 1024  # Voyage AI voyage-3 embedding dimension; overridable via config
VECTOR_SIMILARITY = "cosine"

# All single-property UNIQUE constraints — including Article/IOC, which enforce their composite
# natural key via a computed synthetic property (source_guid_key/value_type_key,
# src/common/natural_keys.py) rather than a NODE KEY constraint. NODE KEY is Enterprise-only and
# is not available on AuraDB Free (this project's production target) — do not "simplify" this back
# to a composite NODE KEY constraint; it will fail on both local Community Edition and AuraDB Free.
UNIQUE_CONSTRAINTS = [
    ("source_url_unique", "Source", "url"),
    ("cve_id_unique", "CVE", "cve_id"),
    ("cwe_id_unique", "CWE", "cwe_id"),
    ("ttp_technique_id_unique", "TTP", "technique_id"),
    ("threat_actor_merge_key_unique", "ThreatActor", "merge_key"),
    ("malware_family_merge_key_unique", "MalwareFamily", "merge_key"),
    ("campaign_merge_key_unique", "Campaign", "merge_key"),
    ("article_source_guid_key", "Article", "source_guid_key"),
    ("ioc_value_type_key", "IOC", "value_type_key"),
    ("cpe_match_id_unique", "CPEMatch", "match_criteria_id"),
    ("asset_key_unique", "Asset", "asset_key"),
]


# Range indexes backing the asset matcher's lookups. Without these, every event-driven
# match and every sweep page planned an AllNodesScan/full label scan over CPEMatch (which
# is the largest label in the live graph — tens of matches per CVE across ~1.7k CVEs).
#
# - The COMPOSITE (vendor, product) indexes serve the matcher's equality lookup on both
#   properties at once (`candidate_matches_for`, `_match_and_assets`).
# - The SINGLE-property CPEMatch indexes serve the autocomplete's `STARTS WITH` prefix
#   scan (`fetch_known_vendor_products`): a composite index only answers equality on its
#   leading properties, so a prefix predicate needs its own single-property index.
#
# All of these rely on vendor/product being case-folded AT WRITE TIME (`_split_cpe`,
# `create_asset`) — a `toLower(n.vendor)` in a query is a function call on the indexed
# property and cannot use any of them.
RANGE_INDEXES = [
    ("cpe_match_vendor_product_index", "CPEMatch", ("vendor", "product")),
    ("cpe_match_vendor_index", "CPEMatch", ("vendor",)),
    ("cpe_match_product_index", "CPEMatch", ("product",)),
    ("asset_vendor_product_index", "Asset", ("vendor", "product")),
]


def _constraint_clause(name: str, label: str, prop: str) -> str:
    return (
        f"CREATE CONSTRAINT {name} IF NOT EXISTS "
        f"FOR (n:{label}) REQUIRE n.{prop} IS UNIQUE"
    )


def _index_clause(name: str, label: str, props: tuple[str, ...]) -> str:
    on = ", ".join(f"n.{p}" for p in props)
    return f"CREATE INDEX {name} IF NOT EXISTS FOR (n:{label}) ON ({on})"


def bootstrap_schema(driver: Driver) -> list[str]:
    applied: list[str] = []
    with driver.session() as session:
        for name, label, prop in UNIQUE_CONSTRAINTS:
            session.run(_constraint_clause(name, label, prop)).consume()
            applied.append(name)

        for name, label, props in RANGE_INDEXES:
            session.run(_index_clause(name, label, props)).consume()
            applied.append(name)

        dimensions = int(
            get_config("embedding_dimensions", default=str(DEFAULT_VECTOR_DIMENSIONS))
        )
        session.run(
            "CREATE VECTOR INDEX article_embedding_index IF NOT EXISTS "
            "FOR (a:Article) ON (a.embedding) "
            "OPTIONS {indexConfig: {"
            "`vector.dimensions`: $dimensions, "
            "`vector.similarity_function`: $similarity}}",
            dimensions=dimensions,
            similarity=VECTOR_SIMILARITY,
        ).consume()
        applied.append("article_embedding_index")

    return applied
