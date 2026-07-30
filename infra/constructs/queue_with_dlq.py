from aws_cdk import Duration, aws_lambda as _lambda, aws_lambda_event_sources as sources
from aws_cdk import aws_sqs as sqs
from constructs import Construct

_DEFAULT_VISIBILITY_TIMEOUT = Duration.seconds(60)

# AWS Lambda validates function timeout <= queue visibility timeout at
# CreateEventSourceMapping time (a runtime AWS validation `cdk synth` cannot catch --
# it's not a template-shape check). AWS recommends at least 6x the function timeout as
# a safety margin (so a Lambda that's still running when SQS would otherwise redeliver
# the message doesn't get a duplicate concurrent invocation of the same message).
_VISIBILITY_TIMEOUT_SAFETY_MARGIN = 6


class QueueWithDlq(Construct):
    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        *,
        queue_name: str,
        max_receive_count: int = 5,
        visibility_timeout: Duration | None = None,
        consumer: _lambda.IFunction | None = None,
        batch_size: int = 10,
    ) -> None:
        super().__init__(scope, construct_id)

        # When a consumer is wired and the caller left `visibility_timeout` at its
        # default (None), derive it from the consumer's own function timeout rather
        # than the fixed 60s default -- a queue's visibility timeout must be >= its
        # consumer Lambda's timeout, or CloudFormation deploy fails at
        # CreateEventSourceMapping time. An explicit `visibility_timeout=` always wins
        # (e.g. a DLQ-only queue with no consumer, or a caller with its own reasoning).
        # `consumer.timeout` is `None` for an *imported* (non-owned) IFunction -- CDK
        # has no way to know its timeout in that case, so fall back to the default.
        consumer_timeout = getattr(consumer, "timeout", None) if consumer is not None else None

        if visibility_timeout is not None:
            resolved_visibility_timeout = visibility_timeout
        elif consumer_timeout is not None:
            resolved_visibility_timeout = Duration.seconds(
                max(
                    _DEFAULT_VISIBILITY_TIMEOUT.to_seconds(),
                    consumer_timeout.to_seconds() * _VISIBILITY_TIMEOUT_SAFETY_MARGIN,
                )
            )
        else:
            resolved_visibility_timeout = _DEFAULT_VISIBILITY_TIMEOUT

        self.dead_letter_queue = sqs.Queue(
            self,
            "Dlq",
            queue_name=f"{queue_name}-dlq",
            retention_period=Duration.days(14),
        )
        self.queue = sqs.Queue(
            self,
            "Queue",
            queue_name=queue_name,
            visibility_timeout=resolved_visibility_timeout,
            dead_letter_queue=sqs.DeadLetterQueue(
                max_receive_count=max_receive_count, queue=self.dead_letter_queue
            ),
        )

        if consumer is not None:
            consumer.add_event_source(
                sources.SqsEventSource(self.queue, batch_size=batch_size)
            )
