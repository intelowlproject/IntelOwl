"""In this file are available the models used to store the data about a channel"""

from django.conf import settings
from django.db import models


class JobChannel(models.Model):
    """Data stored about a job scan.

    * job_id is used to send data to all the channels waiting for the job:
        multiple users waiting for the same job
    * user is used to get the permission to kill or delete the job
    """

    job_id = models.PositiveIntegerField(null=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        null=False,
    )
    channel_name = models.CharField()
