"""
Every other part of the app writes through this graph layer to update the graph.

`writer.py` holds the core function for a graph write. 
`assertion_edges.py`, `evidence_edges.py`, and `structural_edges.py` are the three types of edges that are built on top of it. 
`publish.py` announces every write so that other layers can react to it. 
`recompute.py` handles any confidence recalculations.
"""
