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
]


def _constraint_clause(name: str, label: str, prop: str) -> str:
    return (
        f"CREATE CONSTRAINT {name} IF NOT EXISTS "
        f"FOR (n:{label}) REQUIRE n.{prop} IS UNIQUE"
    )


def bootstrap_schema(driver: Driver) -> list[str]:
    applied: list[str] = []
    with driver.session() as session:
        for name, label, prop in UNIQUE_CONSTRAINTS:
            session.run(_constraint_clause(name, label, prop)).consume()
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
