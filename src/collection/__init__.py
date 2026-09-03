"""
Ingests raw articles and reference data like CVEs, KEV/EPSS scores, ATT&CK data.

The RSS subpackage polls RSS/Atom feeds and security blogs.
The REST subpackage polls REST APIs such as NVD, EPSS, CISA KEV, GHSA, OTX, and abuse.ch.
The STIX subpackage syncs MITRE ATT&CK data.

The source config holds the shared config for use by all three subpackages.
"""
