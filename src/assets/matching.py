"""Pure version-range matching for Asset <-> CVE.CPEMatch (design spec §5 Decision 3).

Best-effort component-wise comparison, not full semver: CPE version strings are not
guaranteed semver, so this splits on "." and compares components numerically where both
sides are digit strings, falling back to lexical string comparison otherwise. Documented
as a known-imperfect heuristic, correct for the large majority of real vendor version
strings.
"""

from itertools import zip_longest


def _compare_component(x: str, y: str) -> int:
    if x.isdigit() and y.isdigit():
        xi, yi = int(x), int(y)
        return (xi > yi) - (xi < yi)
    return (x > y) - (x < y)


def _version_compare(a: str, b: str) -> int:
    """-1 if a<b, 0 if equal, 1 if a>b. Missing trailing components compare as '0'."""
    for x, y in zip_longest(a.split("."), b.split("."), fillvalue="0"):
        cmp = _compare_component(x, y)
        if cmp != 0:
            return cmp
    return 0


def version_satisfies(version: str, match: dict) -> bool:
    """Whether `version` falls inside the range/pin described by one CPEMatch record."""
    if not match.get("vulnerable", True):
        return False

    exact = match.get("version")
    if exact:
        return _version_compare(version, exact) == 0

    start_inc = match.get("version_start_including")
    if start_inc and _version_compare(version, start_inc) < 0:
        return False
    start_exc = match.get("version_start_excluding")
    if start_exc and _version_compare(version, start_exc) <= 0:
        return False
    end_inc = match.get("version_end_including")
    if end_inc and _version_compare(version, end_inc) > 0:
        return False
    end_exc = match.get("version_end_excluding")
    if end_exc and _version_compare(version, end_exc) >= 0:
        return False
    return True
