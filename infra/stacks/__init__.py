"""
There is one CDK stack per backend layer.

The stacks are as follows:
- Foundation Stack handles the DynamoDB tables, graph-write topic, and schema bootstrapping.
- Data Collection Stack handles the ingestion of various sources of data.
- NLP (Natural Language Processing) Stack handles the extraction and processing of ingested data.
- Scoring Stack handles the severity, relevance, and confidence of extractions.
- Interop Stack handles the exporting of data as STIX/TAXII for other tools to use.
- Delivery Stack handles the deployment of HTTP API Gateway and Auth Services.
- Asset Stack handles the matching of user assets against CVE data.

See `infra/app.py` for how they're wired together.
"""
