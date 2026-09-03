"""
This phase works out how entities relate to each other using each story's main article.
`relation_extraction.py` does the extraction. 
`confidence.py` scores how confident we are of the result.
`re_cache.py` skips re-processing an article that hasn't changed.
"""
