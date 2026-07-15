from aws_cdk import Duration, aws_lambda as _lambda, aws_lambda_event_sources as sources
from aws_cdk import aws_sqs as sqs
from constructs import Construct


class QueueWithDlq(Construct):
    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        *,
        queue_name: str,
        max_receive_count: int = 5,
        visibility_timeout: Duration = Duration.seconds(60),
        consumer: _lambda.IFunction | None = None,
        batch_size: int = 10,
    ) -> None:
        super().__init__(scope, construct_id)

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
            visibility_timeout=visibility_timeout,
            dead_letter_queue=sqs.DeadLetterQueue(
                max_receive_count=max_receive_count, queue=self.dead_letter_queue
            ),
        )

        if consumer is not None:
            consumer.add_event_source(
                sources.SqsEventSource(self.queue, batch_size=batch_size)
            )
