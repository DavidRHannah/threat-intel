"""abuse.ch (URLhaus, MalwareBazaar, ThreatFox) normalizers (L1 Task 9).

Per plan §6 (Cross-Cutting Notes) these three feeds share no code beyond the common
`SourceNormalizer` protocol and `handle_response` seam -- three independent
normalizer/process functions in this one file, not a unified "abuse.ch client"
abstraction (their record shapes and implied entities differ enough that unifying them
would cost more than it saves, same reasoning `data-collection-layer/design.md` Part 4
§4 gives for not unifying pagination).

- **URLhaus**: a malware-distribution URL blocklist. Each record `MERGE`s a plain `IOC`
  (`ioc_type="url"`) -- no `MalwareFamily` is implied here (URLhaus's `tags` are free-text
  file-type/family hints, not a canonical family record) per this task's outer scope.
- **MalwareBazaar**: malware sample hashes. Each record `MERGE`s a plain `IOC`
  (`ioc_type="sha256_hash"`) -- same reasoning as URLhaus; its `signature` field is a
  strong family hint but, matching this task's scope decision, is not promoted to a
  `MalwareFamily` node/edge here (only ThreatFox's is, per the brief's explicit call-out).
- **ThreatFox**: the one abuse.ch feed with a first-class malware-family field
  (`malware`/`malware_printable`). Each record `MERGE`s an `IOC` **and** a `MalwareFamily`
  (`merge_key` = normalized `malware_printable`, no MITRE id available from this feed),
  then writes the edge via `src.common.graph.assertion_edges.upsert_authoritative_assertion`
  inside `session.execute_write(...)`, announced via `publish_graph_write`. Direction is
  `MalwareFamily -> IOC` per `technical-specification.md` §3.2. Rel type depends on the
  IOC's own type: a hash IOC (`*_hash`) is a **sample** of the family (`HAS_SAMPLE`); a
  network IOC (`ip:port`/`domain`/`url`) is infrastructure the family **communicates
  with** (`COMMUNICATES_WITH`) -- both rel types are in the spec's edge table for exactly
  this `MalwareFamily->IOC` direction, so the split uses the one that already exists for
  each shape rather than picking one arbitrarily.

Credentials: each feed is configured (and credentialed) as its own `source_id`
(`urlhaus`/`malwarebazaar`/`threatfox`) -- `load_credential(source_id, "api_key")`, never
hardcoded (FR-DC-18). abuse.ch's newer API requires an `Auth-Key` header per feed.

FR-DC-01 (IOC, MalwareFamily).
"""

from dataclasses import dataclass, field
from typing import Any, Protocol

from src.collection.rest.http_errors import handle_response
from src.collection.rest.normalizer import NodeUpsert, read_source_credibility_score
from src.collection.rest.ssm_credentials import load_credential
from src.common import natural_keys
from src.common.config import get_config
from src.common.graph.assertion_edges import upsert_authoritative_assertion
from src.common.graph.publish import publish_graph_write

URLHAUS_SOURCE_ID = "urlhaus"
MALWAREBAZAAR_SOURCE_ID = "malwarebazaar"
THREATFOX_SOURCE_ID = "threatfox"

_HASH_TYPES = {"md5_hash", "sha1_hash", "sha256_hash"}


class _HttpClient(Protocol):
    def get(self, url: str, params: dict | None = None, headers: dict | None = None) -> Any: ...

    def post(self, url: str, data: dict | None = None, headers: dict | None = None) -> Any: ...


def _schema_valid_query_status_ok(body: Any) -> bool:
    return isinstance(body, dict) and body.get("query_status") == "ok"


def _auth_headers(source_id: str) -> dict:
    return {"Auth-Key": load_credential(source_id, "api_key")}


def _alert(_response: Any) -> None:
    # A 401/403 here means the Auth-Key is invalid/revoked -- a hard config error
    # surfaced via the raised NoRetryError; nothing else to publish here.
    pass


# --- URLhaus ---------------------------------------------------------------------


@dataclass
class ParsedUrlhausEntry:
    value: str
    ioc_type: str = "url"
    properties: dict[str, Any] = field(default_factory=dict)


class UrlhausNormalizer:
    def parse(self, raw_response: dict) -> list[ParsedUrlhausEntry]:
        out: list[ParsedUrlhausEntry] = []
        for item in raw_response.get("urls", []):
            url = item.get("url")
            if not url:
                continue
            out.append(
                ParsedUrlhausEntry(
                    value=url,
                    properties={
                        "url_status": item.get("url_status"),
                        "host": item.get("host"),
                        "threat": item.get("threat"),
                        "tags": item.get("tags", []),
                        "date_added": item.get("date_added"),
                    },
                )
            )
        return out

    def normalize(self, raw_response: dict) -> list[NodeUpsert]:
        return [
            NodeUpsert(
                label="IOC",
                natural_key={"value_type_key": natural_keys.ioc_key(p.value, p.ioc_type)},
                properties={"value": p.value, "ioc_type": p.ioc_type, **p.properties},
            )
            for p in self.parse(raw_response)
        ]


def _merge_ioc_tx(tx, value: str, ioc_type: str, properties: dict) -> None:
    key = natural_keys.ioc_key(value, ioc_type)
    tx.run(
        "MERGE (i:IOC {value_type_key: $key}) "
        "SET i.value = $value, i.ioc_type = $ioc_type, i += $props",
        key=key, value=value, ioc_type=ioc_type, props=properties,
    ).consume()


def _urlhaus_url() -> str:
    return get_config(
        "urlhaus_api_base_url", default="https://urlhaus-api.abuse.ch/v1/urls/recent/"
    )


def process_urlhaus(driver, http_client: _HttpClient) -> int:
    """Fetch URLhaus's recent-activity window and MERGE each URL as a plain IOC.
    Returns the count of entries processed."""
    response = http_client.post(_urlhaus_url(), headers=_auth_headers(URLHAUS_SOURCE_ID))
    body = handle_response(response, alert_fn=_alert, schema_validator=_schema_valid_query_status_ok)

    entries = UrlhausNormalizer().parse(body)
    with driver.session() as session:
        for entry in entries:
            session.execute_write(_merge_ioc_tx, entry.value, entry.ioc_type, entry.properties)
    return len(entries)


# --- MalwareBazaar -----------------------------------------------------------------


@dataclass
class ParsedMalwareBazaarEntry:
    value: str
    ioc_type: str = "sha256_hash"
    properties: dict[str, Any] = field(default_factory=dict)


class MalwareBazaarNormalizer:
    def parse(self, raw_response: dict) -> list[ParsedMalwareBazaarEntry]:
        out: list[ParsedMalwareBazaarEntry] = []
        for item in raw_response.get("data", []):
            sha256 = item.get("sha256_hash")
            if not sha256:
                continue
            out.append(
                ParsedMalwareBazaarEntry(
                    value=sha256,
                    properties={
                        "file_name": item.get("file_name"),
                        "file_type": item.get("file_type"),
                        "signature": item.get("signature"),
                        "tags": item.get("tags", []),
                        "first_seen": item.get("first_seen"),
                    },
                )
            )
        return out

    def normalize(self, raw_response: dict) -> list[NodeUpsert]:
        return [
            NodeUpsert(
                label="IOC",
                natural_key={"value_type_key": natural_keys.ioc_key(p.value, p.ioc_type)},
                properties={"value": p.value, "ioc_type": p.ioc_type, **p.properties},
            )
            for p in self.parse(raw_response)
        ]


def _malwarebazaar_url() -> str:
    return get_config(
        "malwarebazaar_api_base_url", default="https://mb-api.abuse.ch/api/v1/"
    )


def process_malwarebazaar(driver, http_client: _HttpClient) -> int:
    """Fetch MalwareBazaar's recent samples and MERGE each hash as a plain IOC.
    Returns the count of entries processed."""
    response = http_client.post(
        _malwarebazaar_url(),
        data={"query": "get_recent", "selector": "time"},
        headers=_auth_headers(MALWAREBAZAAR_SOURCE_ID),
    )
    body = handle_response(response, alert_fn=_alert, schema_validator=_schema_valid_query_status_ok)

    entries = MalwareBazaarNormalizer().parse(body)
    with driver.session() as session:
        for entry in entries:
            session.execute_write(_merge_ioc_tx, entry.value, entry.ioc_type, entry.properties)
    return len(entries)


# --- ThreatFox ---------------------------------------------------------------------


@dataclass
class ParsedThreatFoxEntry:
    value: str
    ioc_type: str
    malware_merge_key: str
    malware_name: str
    ioc_properties: dict[str, Any] = field(default_factory=dict)
    malware_properties: dict[str, Any] = field(default_factory=dict)

    @property
    def rel_type(self) -> str:
        return "HAS_SAMPLE" if self.ioc_type in _HASH_TYPES else "COMMUNICATES_WITH"


def _normalize_family_name(name: str) -> str:
    return name.strip().lower()


class ThreatFoxNormalizer:
    def parse(self, raw_response: dict) -> list[ParsedThreatFoxEntry]:
        out: list[ParsedThreatFoxEntry] = []
        for item in raw_response.get("data", []):
            value = item.get("ioc")
            ioc_type = item.get("ioc_type")
            malware_printable = item.get("malware_printable")
            if not value or not ioc_type or not malware_printable:
                continue
            out.append(
                ParsedThreatFoxEntry(
                    value=value,
                    ioc_type=ioc_type,
                    malware_merge_key=_normalize_family_name(malware_printable),
                    malware_name=malware_printable,
                    ioc_properties={
                        "threat_type": item.get("threat_type"),
                        "confidence_level": item.get("confidence_level"),
                        "first_seen": item.get("first_seen"),
                    },
                    malware_properties={
                        "name": malware_printable,
                        "aliases": [item.get("malware")] if item.get("malware") else [],
                    },
                )
            )
        return out

    def normalize(self, raw_response: dict) -> list[NodeUpsert]:
        upserts: list[NodeUpsert] = []
        for p in self.parse(raw_response):
            upserts.append(
                NodeUpsert(
                    label="IOC",
                    natural_key={"value_type_key": natural_keys.ioc_key(p.value, p.ioc_type)},
                    properties={"value": p.value, "ioc_type": p.ioc_type, **p.ioc_properties},
                )
            )
            upserts.append(
                NodeUpsert(
                    label="MalwareFamily",
                    natural_key={"merge_key": p.malware_merge_key},
                    properties=p.malware_properties,
                )
            )
        return upserts


def _merge_malware_family_tx(tx, merge_key: str, properties: dict) -> None:
    tx.run(
        "MERGE (m:MalwareFamily {merge_key: $key}) SET m += $props",
        key=merge_key, props=properties,
    ).consume()


def _write_threatfox_edge_tx(tx, *, entry: ParsedThreatFoxEntry, now) -> str:
    # Read Source.credibility_score inside this same transaction (never a separate round
    # trip) so it can't observe a stale/uncommitted Source state relative to the edge
    # write it feeds -- see read_source_credibility_score's docstring for the fallback
    # behavior if the Source node is missing.
    credibility_score = read_source_credibility_score(tx, THREATFOX_SOURCE_ID)
    return upsert_authoritative_assertion(
        tx,
        start_label="MalwareFamily",
        start_key={"merge_key": entry.malware_merge_key},
        end_label="IOC",
        end_key={"value_type_key": natural_keys.ioc_key(entry.value, entry.ioc_type)},
        rel_type=entry.rel_type,
        feed_source=THREATFOX_SOURCE_ID,
        credibility_score=credibility_score,
        now=now,
    )


def _threatfox_url() -> str:
    return get_config("threatfox_api_base_url", default="https://threatfox-api.abuse.ch/api/v1/")


def process_threatfox(driver, http_client: _HttpClient, *, now) -> int:
    """Fetch ThreatFox's recent IOCs, MERGE each as an IOC + its MalwareFamily, and write
    the implied `MalwareFamily`->`IOC` edge (`HAS_SAMPLE` for a hash IOC,
    `COMMUNICATES_WITH` for a network IOC) via `upsert_authoritative_assertion`,
    announced via `publish_graph_write`. Returns the count of entries processed.
    """
    response = http_client.post(_threatfox_url(), headers=_auth_headers(THREATFOX_SOURCE_ID))
    body = handle_response(response, alert_fn=_alert, schema_validator=_schema_valid_query_status_ok)

    entries = ThreatFoxNormalizer().parse(body)
    with driver.session() as session:
        for entry in entries:
            session.execute_write(
                _merge_ioc_tx, entry.value, entry.ioc_type, entry.ioc_properties
            )
            session.execute_write(
                _merge_malware_family_tx, entry.malware_merge_key, entry.malware_properties
            )

    with driver.session() as session:
        for entry in entries:
            outcome = session.execute_write(_write_threatfox_edge_tx, entry=entry, now=now)
            publish_graph_write(
                rel_type=entry.rel_type,
                start_key={"merge_key": entry.malware_merge_key},
                end_key={"value_type_key": natural_keys.ioc_key(entry.value, entry.ioc_type)},
                outcome=outcome,
                origin="authoritative",
            )

    return len(entries)
