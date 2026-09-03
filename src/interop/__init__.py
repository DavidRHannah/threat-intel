"""
Exports data as STIX/TAXII for other tools to use.

`taxii_handler.py` serves the TAXII endpoints and builds STIX fresh rather than storing it.
`watermark_handler.py` timestamps every write so that polling clients know what's new. 
`gating.py` and `tlp.py` control what's allowed to be shared.
`withdrawal.py`, `merge_tombstone.py`, and `stix_ids.py` handle the revoking or merging data that was already exported.
"""
