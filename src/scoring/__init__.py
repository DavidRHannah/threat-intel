"""Scores severity, relevance, confidence, and significance using the shared math in `formulas.py`.

The event handler rescores things quickly as new data comes in.
The sweep handler is a daily job that fixes anything that the quick path missed. 
The knobs are used for tuning the scoring parameters.
"""
