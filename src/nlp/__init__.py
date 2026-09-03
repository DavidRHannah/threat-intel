""" 
The pipeline to turn article text into graph data where each stage is its own Lambda.

1. The extraction phase pulls entity mentions out of the text.
2. The resolution phase matches those mentions to existing nodes in the graph.
3. The dedup phase groups articles that are covering the same story.
4. The inference phase works out how the entities in a given story relate to each other.
"""
