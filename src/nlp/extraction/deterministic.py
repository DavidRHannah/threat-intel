"""Deterministic (regex + refang) extraction of CVE, TTP-ID, and IOC mentions.

Pattern-based extractors — exact, cannot hallucinate. Per
`entity-extraction-nlp-layer/extraction-design.md` Part 2:

- CVE / TTP-ID are format-validated only; confidence ~1.0.
- IOCs are refanged (defanged text un-obscured) *before* classification,
  filtered for RFC1918/reserved IPs and a benign-domain allowlist, and a
  defanged indicator scores higher confidence than a bare one (defanging is
  an authorial signal that the value is a real IOC, not incidental text).

`extract_deterministic` is a pure function over `text` — no I/O, no Neo4j
(FR-EX-12 applies to the whole Extraction stage, not just this module, but
this module in particular must stay pure to keep that guarantee simple to
verify).
"""

from __future__ import annotations

import re

from src.common.config import get_config
from src.nlp.messages import RawMention

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")
_TTP_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")

# Zero-width characters attackers sometimes use to break up defanged IOCs.
_ZERO_WIDTH_RE = re.compile(r"[​‌‍﻿]")

# Refang table applied left-to-right; order matters (longer/more-specific
# tokens before shorter ones where they could otherwise partially overlap).
_REFANG_TABLE: list[tuple[str, str]] = [
    ("hxxp", "http"),
    ("[.]", "."),
    ("(dot)", "."),
    ("[dot]", "."),
    ("[at]", "@"),
    ("(at)", "@"),
    ("[:]", ":"),
]

_RFC1918_RESERVED_PREFIXES = (
    "10.",
    "127.",
    "169.254.",
) + tuple(f"172.{i}." for i in range(16, 32)) + tuple(f"192.168.{i}." for i in range(0, 256))

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IPV6_RE = re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b")
_URL_RE = re.compile(r"\bhttps?://[^\s\"'<>]+", re.IGNORECASE)
_EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
_SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
_SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
_MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
# A conservative domain pattern: label.label(.label)*, requires a known-ish
# looking TLD length (2-24) to avoid matching arbitrary "word.word" prose.
_DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}\b"
)


def _refang(text: str) -> str:
    out = _ZERO_WIDTH_RE.sub("", text)
    for defanged, real in _REFANG_TABLE:
        out = out.replace(defanged, real)
    return out


def _is_rfc1918_or_reserved(ip: str) -> bool:
    return ip.startswith(_RFC1918_RESERVED_PREFIXES)


def _benign_domains() -> set[str]:
    raw = get_config("ioc_benign_domains", default="microsoft.com,github.com,google.com")
    return {d.strip().lower() for d in raw.split(",") if d.strip()}


def _classify_ioc(refanged_value: str) -> str | None:
    if _SHA256_RE.fullmatch(refanged_value):
        return "sha256"
    if _SHA1_RE.fullmatch(refanged_value):
        return "sha1"
    if _MD5_RE.fullmatch(refanged_value):
        return "md5"
    if _EMAIL_RE.fullmatch(refanged_value):
        return "email"
    if _URL_RE.match(refanged_value):
        return "url"
    if _IPV4_RE.fullmatch(refanged_value):
        return "ipv4"
    if _IPV6_RE.fullmatch(refanged_value) and ":" in refanged_value:
        return "ipv6"
    if _DOMAIN_RE.fullmatch(refanged_value):
        return "domain"
    return None


def _find_ioc_candidates(text: str) -> list[tuple[str, str, bool]]:
    """Scan `text` for raw (possibly defanged) IOC-shaped substrings.

    Returns a list of (raw_matched_text, refanged_value, was_defanged) tuples.
    Scans the refanged text for shape matches (so defanged values are
    findable at all), and treats a candidate as "was_defanged" if refanging
    changed the substring.
    """
    refanged_text = _refang(text)
    candidates: list[tuple[str, str, bool]] = []
    seen_spans: set[tuple[int, int]] = set()

    for pattern in (
        _SHA256_RE,
        _SHA1_RE,
        _MD5_RE,
        _EMAIL_RE,
        _URL_RE,
        _IPV6_RE,
        _IPV4_RE,
        _DOMAIN_RE,
    ):
        for match in pattern.finditer(refanged_text):
            span = match.span()
            if any(s <= span[0] < e or s < span[1] <= e for s, e in seen_spans):
                continue
            seen_spans.add(span)
            refanged_value = match.group(0)
            # Heuristic: if the same span in the *original* text differs from
            # the refanged text, the original was defanged.
            original_slice = text[max(0, span[0] - 10): span[1] + 10]
            was_defanged = _refang(original_slice) != original_slice
            candidates.append((refanged_value, refanged_value, was_defanged))

    return candidates


def _extract_ioc_mentions(article_id: str, text: str) -> list[RawMention]:
    benign = _benign_domains()
    mentions: list[RawMention] = []

    for _raw, refanged_value, was_defanged in _find_ioc_candidates(text):
        ioc_type = _classify_ioc(refanged_value)
        if ioc_type is None:
            continue

        normalized = refanged_value.lower() if ioc_type != "url" else refanged_value

        if ioc_type in ("ipv4", "ipv6") and _is_rfc1918_or_reserved(refanged_value):
            continue

        if ioc_type == "domain" and normalized in benign:
            # Benign allowlisted domains are dropped outright (per design:
            # "dropped or heavily discounted" — dropping avoids flooding the
            # graph with incidental infra mentions).
            continue

        base_confidence = 0.9 if was_defanged else 0.4
        idx = text.find(refanged_value)
        if idx == -1:
            idx = 0
        span = (idx, idx + len(refanged_value))

        mentions.append(
            RawMention(
                article_id=article_id,
                entity_type="ioc",
                surface_text=refanged_value,
                char_span=span,
                extraction_confidence=base_confidence,
                context_snippet=text[max(0, span[0] - 40): span[1] + 40].strip(),
            )
        )

    return mentions


def extract_deterministic(text: str, article_id: str = "") -> list[RawMention]:
    """Extract CVE, TTP-ID, and IOC mentions from `text` via regex + refang.

    Pure function: no I/O, no Neo4j. Applies within-type dedup keyed on
    `(entity_type, normalized_value)`, keeping the highest-confidence
    `RawMention` for each key (FR-EX-11).
    """
    raw_mentions: list[RawMention] = []

    for match in _CVE_RE.finditer(text):
        raw_mentions.append(
            RawMention(
                article_id=article_id,
                entity_type="cve",
                surface_text=match.group(0).upper(),
                char_span=match.span(),
                extraction_confidence=1.0,
                context_snippet=text[max(0, match.start() - 40): match.end() + 40].strip(),
            )
        )

    for match in _TTP_RE.finditer(text):
        raw_mentions.append(
            RawMention(
                article_id=article_id,
                entity_type="ttp",
                surface_text=match.group(0).upper(),
                char_span=match.span(),
                extraction_confidence=1.0,
                context_snippet=text[max(0, match.start() - 40): match.end() + 40].strip(),
            )
        )

    raw_mentions.extend(_extract_ioc_mentions(article_id, text))

    return _dedup_within_type(raw_mentions)


def _normalize_for_dedup(mention: RawMention) -> str:
    if mention.entity_type in ("cve", "ttp"):
        return mention.surface_text.upper()
    if mention.entity_type == "ioc":
        return mention.surface_text.lower()
    return mention.surface_text.strip().lower()


def _dedup_within_type(mentions: list[RawMention]) -> list[RawMention]:
    """Keep the highest-confidence RawMention per (entity_type, normalized_value).

    Generic over the input list — does not assume the entity_type sets from
    different sources are disjoint (FR-EX-11), even though in practice
    deterministic types (cve/ttp/ioc) and LLM types (threat_actor/
    malware_family) never collide.
    """
    best: dict[tuple[str, str], RawMention] = {}
    for mention in mentions:
        key = (mention.entity_type, _normalize_for_dedup(mention))
        existing = best.get(key)
        if existing is None or mention.extraction_confidence > existing.extraction_confidence:
            best[key] = mention
    return list(best.values())
