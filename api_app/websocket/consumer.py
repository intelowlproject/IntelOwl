import logging

from asgiref.sync import async_to_sync
from channels.generic.websocket import JsonWebsocketConsumer
from channels.layers import get_channel_layer

from api_app.choices import Status
from api_app.models import Job
from api_app.serializers.job import WsJobSerializer
from api_app.websocket.models import JobChannel

logger = logging.getLogger(__name__)


class JobConsumer(JsonWebsocketConsumer):
    def connect(self) -> None:
        logger.debug(f"{self.scope=}")
        user = self.scope["user"]
        job_id = self.scope["url_route"]["kwargs"]["job_id"]
        logger.info(f"user: {user} requested the analysis for the job {job_id}")
        try:
            job = Job.objects.get(id=job_id)
        except Job.DoesNotExist:
            logger.error(f"user: {user} request the non-existing job: {job_id}")
            self.close(code=4040)
        else:
            self.accept()
            JobChannel.objects.create(
                job_id=job_id, user=user, channel_name=self.channel_name
            )
            JobConsumer.serialize_and_send_job(job)

    def disconnect(self, close_code) -> None:
        user = self.scope["user"]
        job_id = self.scope["url_route"]["kwargs"]["job_id"]
        JobChannel.objects.filter(channel_name=self.channel_name).delete()
        logger.info(
            f"user: {user} disconnected for the job: {job_id}. Close code: {close_code}"
        )
        self.close(code=close_code)

    def receive_json(self, content) -> None:
        user = self.scope["user"]
        logger.warning(
            f"user {user} send {content} to the websocket, this shouldn't happen"
        )

    def send_job(self, event) -> None:
        job_data = event["job"]
        logger.debug(f"job data: {job_data}")
        self.send_json(content=job_data)
        if job_data["status"] in Status.final_statuses():
            logger.debug("job sent to the client and terminated, close ws")
            self.close()

    @classmethod
    def _generate_group_name(cls, job_id: int) -> str:
        return f"job-{job_id}"

    @classmethod
    def serialize_and_send_job(cls, job: Job) -> None:
        # send data
        channel_layer = get_channel_layer()
        for channel in JobChannel.objects.filter(job_id=job.id):
            logger.debug(
                f"send data for the job: {job.id} "
                f"to the user: {channel.user.username} "
                f"over the channel: {channel.channel_name}"
            )
            job_serializer = WsJobSerializer(job, context={"channel": channel})
            job_data = job_serializer.data
            async_to_sync(channel_layer.send)(
                channel.channel_name,
                {"type": "send.job", "job": job_data},
            )
