"""Backend consists of a pipeline of Lambdas to convert security feeds into a scored threat graph that is also searchable.

Each subpackage is one stage of the pipeline:

- `common` - shared database connection, config, and graph-writing helpers.
- `collection` - pulls in RSS/REST feeds and MITRE ATT&CK data.
- `nlp` - extracts, resolves, dedups, and links entities from articles.
- `scoring` - scores severity, relevance, confidence, and significance.
- `interop` - exports data as STIX/TAXII.
- `delivery` - the API behind the dashboard and integrations.
- `assets` - tracks what each user owns, matched against CVE data.

See the "Architecture" page in the docs site for how these talk to each other.
"""
