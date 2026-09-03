"""
Polls RSS/Atom feeds. 

`poller.py` checks every active feed and flags new or changed articles. 
`dedup_state.py` remembers what has already been seen.
`extraction.py` pulls the clean article text out of each feed entry.
"""
