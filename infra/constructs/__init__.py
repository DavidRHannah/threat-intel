"""
This package consists of CDK constructs that are shared across multiple stacks. 

`queue_with_dlq.py` is an SQS queue paired with its dead-letter queue. 
`graph_writes_topic.py` is the shared graph-writes SNS topic and its filtered subscriptions. 
`iam_helpers.py` consists of common IAM grant patterns. 
`schema_bootstrap_job.py` is the custom resource that applies the Neo4j schema on deploy.
"""
