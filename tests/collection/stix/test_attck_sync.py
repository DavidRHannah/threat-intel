"""Integration tests for the MITRE ATT&CK STIX sync (L1 Task 11, Category C).

Runs against a real local Neo4j (docker compose up -d neo4j). `fetch_index_fn` /
`fetch_bundle_fn` are injected fakes returning already-parsed fixture JSON -- no live
GitHub calls (per the module's contract-seam docstring).

- FR-DC-26: an unchanged index version means `fetch_bundle_fn` is never called for that
  domain, even though `fetch_index_fn` is called for all three.
- FR-DC-27: a version bump downloads the bundle and MERGEs all four object types plus
  their `USES`/`ATTRIBUTED_TO` edges.
- FR-DC-28: a re-sync with a bundle carrying revoked/deprecated flags SETs those flags
  without deleting the node or its prior edges.
- FR-DC-01: re-running the same bundle produces exactly one node per fixture object (no
  duplicates from re-MERGE).

Only `enterprise-attack` has fixture bundles; `mobile-attack`/`ics-attack` are exercised
only for the index-check / no-bundle-fetch behavior (their index version is set equal to
`last_ingested_versions` in every test so no bundle fetch for them is ever expected) --
per the brief's fixture scope (one domain's bundles only).
"""

import copy
import json
import uuid
from pathlib import Path

import pytest

from src.collection.stix.attck_sync import DOMAINS, sync_attck
from src.common.config import get_config
from src.common.neo4j_driver import close_driver, get_driver
from src.common.schema_bootstrap import bootstrap_schema

FIXTURES = Path(__file__).parent.parent / "fixtures"

TTP_KEY = "T1566"
THREAT_ACTOR_KEY = "G0007"
MALWARE_KEY = "S0154"
CAMPAIGN_KEY = "C0001"


def _load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


class FetchFns:
    """Records calls; returns fixture bundles/indexes keyed by domain."""

    def __init__(self, index_by_domain: dict, bundle_by_domain: dict | None = None):
        self._index_by_domain = index_by_domain
        self._bundle_by_domain = bundle_by_domain or {}
        self.index_calls: list[str] = []
        self.bundle_calls: list[str] = []

    def fetch_index(self, domain: str) -> dict:
        self.index_calls.append(domain)
        return self._index_by_domain[domain]

    def fetch_bundle(self, domain: str) -> dict:
        self.bundle_calls.append(domain)
        return self._bundle_by_domain[domain]


@pytest.fixture
def base_index() -> dict:
    return _load("attck_collection_index.json")


@pytest.fixture
def driver():
    d = get_driver()
    d.verify_connectivity()
    bootstrap_schema(d)
    _cleanup(d)
    yield d
    _cleanup(d)
    close_driver()


def _cleanup(d) -> None:
    with d.session() as s:
        s.run(
            "MATCH (n) WHERE "
            "(n:TTP AND n.technique_id = $ttp) OR "
            "(n:ThreatActor AND n.merge_key = $actor) OR "
            "(n:MalwareFamily AND n.merge_key = $malware) OR "
            "(n:Campaign AND n.merge_key = $campaign) "
            "DETACH DELETE n",
            ttp=TTP_KEY, actor=THREAT_ACTOR_KEY, malware=MALWARE_KEY, campaign=CAMPAIGN_KEY,
        ).consume()


def _node_count(d, label: str, key_prop: str, key_value: str) -> int:
    with d.session() as s:
        return s.run(
            f"MATCH (n:{label} {{{key_prop}: $v}}) RETURN count(n) AS c",
            v=key_value,
        ).single()["c"]


def _edge_exists(d, start_label, start_key_prop, start_key, rel_type, end_label, end_key_prop, end_key) -> bool:
    with d.session() as s:
        row = s.run(
            f"MATCH (a:{start_label} {{{start_key_prop}: $sk}})"
            f"-[r:{rel_type}]->"
            f"(b:{end_label} {{{end_key_prop}: $ek}}) "
            "RETURN count(r) AS c",
            sk=start_key, ek=end_key,
        ).single()
        return row["c"] == 1


def _synthetic_uses_bundle(n: int, *, actor_id: str = "GBATCH") -> tuple[dict, str, list[str]]:
    """A minimal synthetic STIX bundle with one intrusion-set `uses` n distinct
    attack-patterns -- n USES edges that all share one (ThreatActor, TTP) group, so
    batching them is actually exercised (the real fixture bundle has only one
    relationship per group, which can't distinguish batched from unbatched).

    Returns (bundle_raw, actor_merge_key, [technique_ids]).
    """
    actor_stix_id = f"intrusion-set--{uuid.uuid4()}"
    technique_ids = [f"TBATCH{i}" for i in range(n)]
    objects = [
        {
            "type": "intrusion-set",
            "spec_version": "2.1",
            "id": actor_stix_id,
            "created": "2020-01-01T00:00:00.000Z",
            "modified": "2020-01-01T00:00:00.000Z",
            "name": "Batch Test Actor",
            "external_references": [
                {"source_name": "mitre-attack", "external_id": actor_id,
                 "url": "https://attack.mitre.org/groups/" + actor_id}
            ],
            "x_mitre_deprecated": False,
            "revoked": False,
        }
    ]
    for tid in technique_ids:
        tp_stix_id = f"attack-pattern--{uuid.uuid4()}"
        objects.append({
            "type": "attack-pattern",
            "spec_version": "2.1",
            "id": tp_stix_id,
            "created": "2020-01-01T00:00:00.000Z",
            "modified": "2020-01-01T00:00:00.000Z",
            "name": f"Batch Technique {tid}",
            "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "execution"}],
            "external_references": [
                {"source_name": "mitre-attack", "external_id": tid,
                 "url": "https://attack.mitre.org/techniques/" + tid}
            ],
            "x_mitre_deprecated": False,
            "revoked": False,
        })
        objects.append({
            "type": "relationship",
            "spec_version": "2.1",
            "id": f"relationship--{uuid.uuid4()}",
            "created": "2020-01-01T00:00:00.000Z",
            "modified": "2020-01-01T00:00:00.000Z",
            "relationship_type": "uses",
            "source_ref": actor_stix_id,
            "target_ref": tp_stix_id,
        })
    bundle = {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "spec_version": "2.1", "objects": objects}
    return bundle, actor_id, technique_ids


class _CountingSession:
    """Wraps one real, kept-open Neo4j session, counting `execute_write` calls -- the
    round-trip unit `_sync_domain_bundle` issues once per node-write batch and once per
    edge-write batch. `driver.session()` is monkeypatched to always return this same
    instance, and production code opens/closes a `with driver.session()` block more than
    once per sync, so `__exit__` deliberately does NOT close the underlying session --
    the caller closes it once, after the sync completes."""

    def __init__(self, session):
        self._session = session
        self.calls = 0

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False

    def execute_write(self, *args, **kwargs):
        self.calls += 1
        return self._session.execute_write(*args, **kwargs)


class TestEdgeWriteBatching:
    """Regression coverage for the production bug: `_sync_domain_bundle` used to call
    `execute_write` once per node AND once per relationship, which against remote AuraDB
    could not finish `enterprise-attack`'s ~25k relationships inside the Lambda timeout
    (three consecutive 600s runs, zero forward progress -- see CLAUDE.md Current State).
    """

    def test_batches_writes_instead_of_one_execute_write_per_row(self, monkeypatch, driver, base_index):
        monkeypatch.setenv("CROSSROADS_ATTCK_BATCH_SIZE", "3")
        get_config.cache_clear()

        n = 10
        bundle, actor_key, technique_ids = _synthetic_uses_bundle(n)
        bumped_index = copy.deepcopy(base_index)
        bumped_index["enterprise-attack"]["version"] = "batch-test"
        fns = FetchFns(index_by_domain=bumped_index, bundle_by_domain={"enterprise-attack": bundle})
        last_ingested = {
            "enterprise-attack": None,
            "mobile-attack": bumped_index["mobile-attack"]["version"],
            "ics-attack": bumped_index["ics-attack"]["version"],
        }

        with driver.session() as s:
            s.run(
                "MATCH (n) WHERE (n:ThreatActor AND n.merge_key = $a) OR "
                "(n:TTP AND n.technique_id STARTS WITH 'TBATCH') DETACH DELETE n",
                a=actor_key,
            ).consume()

        real_session = driver.session
        underlying = real_session()
        counting = _CountingSession(underlying)
        monkeypatch.setattr(driver, "session", lambda *a, **k: counting)
        try:
            sync_attck(driver, fns.fetch_index, fns.fetch_bundle, last_ingested)
        finally:
            monkeypatch.setattr(driver, "session", real_session)
            underlying.close()
            get_config.cache_clear()

        # 11 node writes (1 actor + 10 techniques) batched at 3/round-trip: ceil(1/3) +
        # ceil(10/3) == 1 + 4 == 5. 10 edge writes, all one group, batched at 3/round-trip:
        # ceil(10/3) == 4. Total 9 -- not 21 (one per node + one per edge, the old shape).
        assert counting.calls == 9

        assert _node_count(driver, "ThreatActor", "merge_key", actor_key) == 1
        for tid in technique_ids:
            assert _node_count(driver, "TTP", "technique_id", tid) == 1
        for tid in technique_ids:
            assert _edge_exists(
                driver, "ThreatActor", "merge_key", actor_key, "USES", "TTP", "technique_id", tid
            )

        with driver.session() as s:
            s.run(
                "MATCH (n) WHERE (n:ThreatActor AND n.merge_key = $a) OR "
                "(n:TTP AND n.technique_id STARTS WITH 'TBATCH') DETACH DELETE n",
                a=actor_key,
            ).consume()


class TestUnrecognisedStixObjects:
    def test_unrecognised_custom_objects_do_not_crash_the_sync(self, driver, base_index):
        """Real ATT&CK bundles are full of MITRE's own custom types (x-mitre-tactic,
        x-mitre-matrix, x-mitre-data-source, ...) that `stix2.parse` returns as plain
        dicts, not parsed objects -- `dict` has no `.type` attribute. Reproduced live
        against the real deployed Lambda (2026-08-15): `AttackPatternError: 'dict'
        object has no attribute 'type'` on the very first invocation after this sync's
        batching fix landed, because that dict-vs-object handling was fixed on a
        worktree branch (353d69b) that was never merged to main, so this refactor was
        built on top of the still-broken version.
        """
        v1_bundle = _load("attck_enterprise_bundle_v1.json")
        bundle_with_custom_type = copy.deepcopy(v1_bundle)
        bundle_with_custom_type["objects"].append({
            "type": "x-mitre-tactic",
            "id": "x-mitre-tactic--00000000-0000-0000-0000-000000000000",
            "spec_version": "2.1",
            "created": "2020-01-01T00:00:00.000Z",
            "modified": "2020-01-01T00:00:00.000Z",
            "name": "Custom Tactic",
            "x_mitre_shortname": "custom-tactic",
        })
        bumped_index = copy.deepcopy(base_index)
        bumped_index["enterprise-attack"]["version"] = "14.2"
        fns = FetchFns(
            index_by_domain=bumped_index,
            bundle_by_domain={"enterprise-attack": bundle_with_custom_type},
        )
        last_ingested = {
            "enterprise-attack": "14.1",
            "mobile-attack": bumped_index["mobile-attack"]["version"],
            "ics-attack": bumped_index["ics-attack"]["version"],
        }

        result = sync_attck(driver, fns.fetch_index, fns.fetch_bundle, last_ingested)

        assert result == {"enterprise-attack": "14.2"}
        assert _node_count(driver, "TTP", "technique_id", TTP_KEY) == 1
        assert _node_count(driver, "ThreatActor", "merge_key", THREAT_ACTOR_KEY) == 1


class TestIncrementalWatermark:
    def test_domain_watermark_is_persisted_as_each_domain_completes(self, driver, base_index):
        """Ported from worktree branch `353d69b` (never merged to main -- also missing
        until this fix, alongside the dict-vs-object bug above). The handler used to
        persist `last_ingested_versions` only AFTER all three domains finished, so a run
        that died partway (the real Lambda hit its 600s cap during mobile/ics) banked
        nothing -- every later run re-synced enterprise from scratch, hit the cap again,
        and never converged. Progress must be durable per domain.
        """
        v1_bundle = _load("attck_enterprise_bundle_v1.json")
        bumped_index = copy.deepcopy(base_index)
        for d in DOMAINS:
            bumped_index[d]["version"] = "14.2"

        def fetch_index(domain):
            return bumped_index[domain]

        def fetch_bundle(domain):
            if domain == "enterprise-attack":
                return v1_bundle
            raise RuntimeError(f"{domain} exploded")  # simulates the timeout/failure

        persisted: list[tuple[str, str]] = []
        last_ingested = {d: "14.1" for d in DOMAINS}

        with pytest.raises(RuntimeError):
            sync_attck(
                driver, fetch_index, fetch_bundle, last_ingested,
                on_domain_synced=lambda domain, version: persisted.append((domain, version)),
            )

        # enterprise finished before the failure, so its watermark is already banked.
        assert persisted == [("enterprise-attack", "14.2")]


class TestIndexVersionGating:
    def test_unchanged_version_never_fetches_bundle(self, driver, base_index):
        fns = FetchFns(index_by_domain=base_index)
        last_ingested = {d: base_index[d]["version"] for d in DOMAINS}

        result = sync_attck(driver, fns.fetch_index, fns.fetch_bundle, last_ingested)

        # FR-DC-26: the index is checked for all three domains regardless...
        assert sorted(fns.index_calls) == sorted(DOMAINS)
        # ...but since nothing changed, the (much larger) bundle is never downloaded --
        # a real call-count assertion, not an inference from sync completing.
        assert fns.bundle_calls == []
        assert result == {}


class TestFullResync:
    def test_version_bump_merges_all_object_types_and_edges(self, driver, base_index):
        v1_bundle = _load("attck_enterprise_bundle_v1.json")
        bumped_index = copy.deepcopy(base_index)
        bumped_index["enterprise-attack"]["version"] = "14.2"
        fns = FetchFns(
            index_by_domain=bumped_index,
            bundle_by_domain={"enterprise-attack": v1_bundle},
        )
        # mobile/ics stay at their "already ingested" version so only enterprise's bundle
        # is fetched -- this task's fixtures cover enterprise-attack only.
        last_ingested = {
            "enterprise-attack": "14.1",
            "mobile-attack": bumped_index["mobile-attack"]["version"],
            "ics-attack": bumped_index["ics-attack"]["version"],
        }

        result = sync_attck(driver, fns.fetch_index, fns.fetch_bundle, last_ingested)

        assert fns.bundle_calls == ["enterprise-attack"]
        assert result == {"enterprise-attack": "14.2"}

        assert _node_count(driver, "TTP", "technique_id", TTP_KEY) == 1
        assert _node_count(driver, "ThreatActor", "merge_key", THREAT_ACTOR_KEY) == 1
        assert _node_count(driver, "MalwareFamily", "merge_key", MALWARE_KEY) == 1
        assert _node_count(driver, "Campaign", "merge_key", CAMPAIGN_KEY) == 1

        # USES: ThreatActor->TTP, MalwareFamily->TTP, Campaign->MalwareFamily
        assert _edge_exists(
            driver, "ThreatActor", "merge_key", THREAT_ACTOR_KEY, "USES", "TTP", "technique_id", TTP_KEY
        )
        assert _edge_exists(
            driver, "MalwareFamily", "merge_key", MALWARE_KEY, "USES", "TTP", "technique_id", TTP_KEY
        )
        assert _edge_exists(
            driver, "Campaign", "merge_key", CAMPAIGN_KEY, "USES", "MalwareFamily", "merge_key", MALWARE_KEY
        )
        # ATTRIBUTED_TO: Campaign->ThreatActor
        assert _edge_exists(
            driver, "Campaign", "merge_key", CAMPAIGN_KEY, "ATTRIBUTED_TO",
            "ThreatActor", "merge_key", THREAT_ACTOR_KEY,
        )

    def test_repeated_sync_produces_no_duplicate_nodes(self, driver, base_index):
        """FR-DC-01: running the v1 sync twice yields exactly one node per fixture
        object -- MERGE, never a blind create."""
        v1_bundle = _load("attck_enterprise_bundle_v1.json")
        index = copy.deepcopy(base_index)

        def run_once():
            fns = FetchFns(
                index_by_domain=index,
                bundle_by_domain={"enterprise-attack": v1_bundle},
            )
            # Empty last_ingested each time forces a real re-sync (re-download +
            # re-MERGE of the identical bundle), which is exactly what's under test.
            last_ingested = {
                "enterprise-attack": None,
                "mobile-attack": index["mobile-attack"]["version"],
                "ics-attack": index["ics-attack"]["version"],
            }
            sync_attck(driver, fns.fetch_index, fns.fetch_bundle, last_ingested)

        run_once()
        run_once()

        assert _node_count(driver, "TTP", "technique_id", TTP_KEY) == 1
        assert _node_count(driver, "ThreatActor", "merge_key", THREAT_ACTOR_KEY) == 1
        assert _node_count(driver, "MalwareFamily", "merge_key", MALWARE_KEY) == 1
        assert _node_count(driver, "Campaign", "merge_key", CAMPAIGN_KEY) == 1


class TestDeprecatedRevokedFlagging:
    def test_revoked_and_deprecated_objects_are_flagged_not_deleted(self, driver, base_index):
        v1_bundle = _load("attck_enterprise_bundle_v1.json")
        v2_bundle = _load("attck_enterprise_bundle_v2_with_revocation.json")
        index = copy.deepcopy(base_index)

        # Seed v1 first so there's a prior state (with edges) to prove survives intact.
        fns_v1 = FetchFns(index_by_domain=index, bundle_by_domain={"enterprise-attack": v1_bundle})
        last_ingested = {
            "enterprise-attack": None,
            "mobile-attack": index["mobile-attack"]["version"],
            "ics-attack": index["ics-attack"]["version"],
        }
        sync_attck(driver, fns_v1.fetch_index, fns_v1.fetch_bundle, last_ingested)

        # Re-sync with the revocation bundle (a fresh version bump).
        bumped_index = copy.deepcopy(index)
        bumped_index["enterprise-attack"]["version"] = "14.2"
        fns_v2 = FetchFns(
            index_by_domain=bumped_index, bundle_by_domain={"enterprise-attack": v2_bundle}
        )
        last_ingested_after_v1 = {
            "enterprise-attack": "14.1",
            "mobile-attack": index["mobile-attack"]["version"],
            "ics-attack": index["ics-attack"]["version"],
        }
        sync_attck(driver, fns_v2.fetch_index, fns_v2.fetch_bundle, last_ingested_after_v1)

        with driver.session() as s:
            malware = s.run(
                "MATCH (m:MalwareFamily {merge_key: $k}) RETURN m", k=MALWARE_KEY
            ).single()["m"]
            ttp = s.run(
                "MATCH (t:TTP {technique_id: $k}) RETURN t", k=TTP_KEY
            ).single()["t"]

        # Revoked (MalwareFamily / Cobalt Strike, S0154)
        assert malware["is_revoked"] is True
        assert malware["revoked_by"] == "S0621"
        # Deprecated (TTP / Phishing, T1566)
        assert ttp["is_deprecated"] is True

        # Still present (never deleted) with prior edges intact.
        assert _node_count(driver, "MalwareFamily", "merge_key", MALWARE_KEY) == 1
        assert _node_count(driver, "TTP", "technique_id", TTP_KEY) == 1
        assert _edge_exists(
            driver, "MalwareFamily", "merge_key", MALWARE_KEY, "USES", "TTP", "technique_id", TTP_KEY
        )
        assert _edge_exists(
            driver, "Campaign", "merge_key", CAMPAIGN_KEY, "USES", "MalwareFamily", "merge_key", MALWARE_KEY
        )
        assert _edge_exists(
            driver, "ThreatActor", "merge_key", THREAT_ACTOR_KEY, "USES", "TTP", "technique_id", TTP_KEY
        )
        assert _edge_exists(
            driver, "Campaign", "merge_key", CAMPAIGN_KEY, "ATTRIBUTED_TO",
            "ThreatActor", "merge_key", THREAT_ACTOR_KEY,
        )
