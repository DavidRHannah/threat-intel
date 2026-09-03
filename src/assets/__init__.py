"""
Tracks each user's assets (vendor/product/version) and matches them against CVE data.

`event_handler.py` matches new CVE data against assets as it comes in.
`sweep_handler.py` is a daily job that double-checks matches and removes any that no longer hold.
`matcher.py` and `matching.py` handle the matching logic.
`store.py` handles the basic create/read/update/delete for assets.
"""
