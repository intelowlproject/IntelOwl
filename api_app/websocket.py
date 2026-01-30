import logging
from typing import List

from asgiref.sync import async_to_sync
from channels.generic.websocket import JsonWebsocketConsumer
from channels.layers import get_channel_layer
from django.contrib.auth import get_user_model
from django.utils.functional import cached_property

from api_app.choices import Status
from api_app.models import Job
from api_app.serializers.job import WsJobSerializer
from certego_saas.apps.organization.membership import Membership

User = get_user_model()


logger = logging.getLogger(__name__)


class JobConsumer(JsonWebsocketConsumer):
    """
    WebSocket consumer for handling real-time job updates.

    This consumer handles WebSocket connections for users to receive updates
    about jobs. It manages group subscriptions based on user permissions and
    job status.
    """

    class JobChannelGroups:
        """
        Helper class to manage channel groups for a job.

        This class defines channel groups that users can join to receive
        updates about a specific job. It provides methods to determine the
        appropriate group for a user based on their permissions.
        """

        def __init__(self, job: Job) -> None:
            """
            Initializes the JobChannelGroups with the given job.

            Args:
                job (Job): The job instance for which the groups are managed.
            """
            self._job = job

        @cached_property
        def job_group_name(self) -> str:
            """
            Returns the name of the general group for the job.

            Returns:
                str: The name of the general group.
            """
            return f"job-{self._job.id}"

        @cached_property
        def job_group_perm_name(self) -> str:
            """
            Returns the name of the permission-based group for the job.

            Returns:
                str: The name of the permission-based group.
            """
            return f"{self.job_group_name}-perm"

        @cached_property
        def group_list(self) -> List[str]:
            """
            Returns a list of all groups related to the job.

            Returns:
                List[str]: The list of group names.
            """
            return [self.job_group_name, self.job_group_perm_name]

        def get_group_for_user(self, user: User) -> str:
            """
            Determines the appropriate group for the user based on permissions.

            Args:
                user (User): The user for whom the group is being determined.

            Returns:
                str: The name of the group the user should join.
            """
            try:
                is_member = self._job.user.membership.organization.user_has_membership(user)
            except Membership.DoesNotExist:
                is_member = False
            return self.job_group_perm_name if self._job.user == user or is_member else self.job_group_name

    def connect(self) -> None:
        """
        Handles the WebSocket connection process.

        This method is called when a new WebSocket connection is established.
        It authenticates the user, retrieves the job, and adds the user to the
        appropriate channel group based on permissions.
        """
        logger.debug(f"{self.scope=}")
        user: User = self.scope["user"]
        job_id = self.scope["url_route"]["kwargs"]["job_id"]
        logger.info(f"user: {user} requested the analysis for the job {job_id}")
        try:
            job = Job.objects.get(id=job_id)
        except Job.DoesNotExist:
            logger.error(f"user: {user} request the non-existing job: {job_id}")
            self.close(code=4040)
        else:
            self.accept()
            subscribed_group = self.JobChannelGroups(job).get_group_for_user(user)
            async_to_sync(self.channel_layer.group_add)(
                subscribed_group,
                self.channel_name,
            )
            logger.debug(f"user: {user} added to the group: {subscribed_group}")
            JobConsumer.serialize_and_send_job(job)

    def disconnect(self, close_code) -> None:
        """
        Handles the WebSocket disconnection process.

        This method is called when the WebSocket connection is closed. It
        removes the user from the appropriate channel group and logs the
        disconnection.

        Args:
            close_code: The WebSocket close code.
        """
        user: User = self.scope["user"]
        job_id = self.scope["url_route"]["kwargs"]["job_id"]
        try:
            job = Job.objects.get(id=job_id)
        except Job.DoesNotExist:
            logger.warning(
                f"close ws by the user: {user} for a non-existing job "
                "This happens in case user tried to open a conn to a non existing job"
            )
            subscribed_group = ""
        else:
            subscribed_group = self.JobChannelGroups(job).get_group_for_user(user)
            async_to_sync(self.channel_layer.group_discard)(
                subscribed_group,
                self.channel_name,
            )
        logger.debug(
            f"user: {user} disconnected from the group: {subscribed_group}. Close code: {close_code}"
        )
        self.close(code=close_code)

    def send_job(self, event) -> None:
        """
        Sends job data to the WebSocket client.

        This method is called when there is an update to the job. It sends the
        serialized job data to the client and closes the WebSocket connection
        if the job status is final.

        Args:
            event: The event data containing the job information.
        """
        job_data = event["job"]
        logger.debug(f"job data: {job_data}")
        self.send_json(content=job_data)
        if job_data["status"] in Status.final_statuses():
            logger.debug("job sent to the client and terminated, close ws")
            self.close()

    @classmethod
    def serialize_and_send_job(cls, job: Job) -> None:
        """
        Serializes the job and sends it to the appropriate channel groups.

        This method is called to send the job data to all relevant groups,
        depending on the job's status and associated permissions.

        Args:
            job (Job): The job instance to be serialized and sent.
        """
        # send data
        groups = cls.JobChannelGroups(job)
        groups_list = groups.group_list
        channel_layer = get_channel_layer()
        logger.debug(f"send data for the job: {job.id} to the groups: {groups_list}")
        for group in groups_list:
            logger.debug(f"send data to the group: {group}")
            job_serializer = WsJobSerializer(job, context={"permissions": "perm" in group})
            job_data = job_serializer.data
            async_to_sync(channel_layer.group_send)(
                group,
                {"type": "send.job", "job": job_data},
            )
