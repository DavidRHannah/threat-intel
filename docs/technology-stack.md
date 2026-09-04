# Technology Stack

This application is a Python-based, serverless threat-intelligence platform.
It combines an event-driven AWS backend, a Neo4j threat graph, and a React dashboard.

## At a glance

| Area | Technologies |
|---|---|
| Application runtime | Python 3.12, Node.js (for the frontend toolchain) |
| Backend compute | AWS Lambda |
| Infrastructure as code | AWS CDK v2 and Constructs |
| Data stores | Neo4j 5, Amazon DynamoDB |
| Messaging and scheduling | Amazon SNS, Amazon SQS, Amazon EventBridge, AWS Step Functions |
| APIs and authentication | Amazon API Gateway HTTP APIs, Amazon Cognito |
| Frontend | React 19, Vite 8, React Router |
| Documentation | MkDocs and Material for MkDocs |

## Languages and application frameworks

- **Python 3.12** is used for collection, NLP, scoring, STIX/TAXII interoperability, delivery APIs, and CDK infrastructure definitions.
- **React 19** provides the single-page dashboard.
- **React Router** manages client-side navigation.
- **TanStack React Query** manages server-state fetching and caching in the dashboard.
- **Vite 8** is the frontend development server and production build tool.

## Backend libraries

| Library | Purpose |
|---|---|
| `neo4j` | Neo4j Bolt driver for graph reads and writes. |
| `boto3` | AWS SDK used by Lambda handlers for AWS services. |
| `feedparser` | RSS and Atom feed parsing. |
| `httpx` | HTTP client for REST-based threat-intelligence sources. |
| `stix2` | STIX 2 object handling and threat-intelligence interchange. |
| `trafilatura` | Article and web-page content extraction. |
| `PyYAML` | Source and application configuration parsing. |
| `anthropic` | Optional LLM-assisted entity and relationship extraction. |

## Frontend libraries

| Library | Purpose |
|---|---|
| `axios` | HTTP client for dashboard API requests. |
| `cytoscape` and `react-cytoscapejs` | Interactive threat-graph visualizations. |
| `d3` | Custom data visualizations and chart utilities. |
| `recharts` | Dashboard charts. |
| `lucide-react` | UI icon set. |
| `react-markdown` | Markdown rendering in the dashboard. |

## Cloud services

The deployed application is built with AWS CDK and organized into the stacks described in [Infrastructure](infra.md).

| Service | Role in Crossroads |
|---|---|
| AWS Lambda | Runs collectors, NLP stages, scoring jobs, APIs, and maintenance handlers. |
| Amazon SNS | Publishes `graph-writes` notifications to downstream consumers. |
| Amazon SQS | Buffers the collection and NLP pipelines and provides dead-letter queue support. |
| Amazon DynamoDB | Stores operational state, feed checkpoints, caches, and export state. |
| Amazon EventBridge | Schedules pollers and periodic processing jobs. |
| AWS Step Functions | Coordinates multi-step and scheduled workflows. |
| Amazon API Gateway | Exposes the dashboard and TAXII HTTP APIs. |
| Amazon Cognito | Supplies JWT authentication for protected APIs. |
| AWS Systems Manager Parameter Store | Holds deployment configuration and secure connection settings. |

## Data and local services

- **Neo4j 5** is the primary threat graph database. Production code connects through the Bolt driver and local development runs Neo4j with the APOC plugin enabled.
- **DynamoDB Local** is included alongside Neo4j in `docker-compose.yml` for local development.
- **Docker Compose** starts the local database services.

## Development, quality, and documentation tools

- **AWS CDK v2** and **Constructs** define and synthesize the infrastructure.
- **pytest** is the backend test runner.
- **moto** supplies AWS-service mocks for tests.
- **Ruff** provides Python linting.
- **oxlint** lints the frontend.
- **MkDocs** builds the project documentation and generated Python API reference.

## External threat-intelligence services

Collection and enrichment integrate with public threat-intelligence sources including
NVD, CISA KEV, EPSS, GitHub Security Advisories, AlienVault OTX, abuse.ch, MITRE ATT&CK,
and configured RSS/Atom feeds. These integrations are application data sources rather
than deployed platform services.

For the data flow these tools support, see [Architecture](architecture.md). 
For local commands and configuration, see the [Runbook](runbook.md).
