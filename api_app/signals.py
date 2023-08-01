# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
from django.db import models
from django.dispatch import receiver

from api_app.helpers import calculate_md5
from api_app.models import Job


@receiver(models.signals.pre_save, sender=Job)
def pre_save(sender, instance: Job, **kwargs):
    if not instance.md5:
        instance.md5 = calculate_md5(
            instance.file.read()
            if instance.is_sample
            else instance.observable_name.encode("utf-8")
        )


@receiver(models.signals.pre_delete, sender=Job)
def delete_file(sender, instance: Job, **kwargs):
    if instance.file:
        instance.file.delete()
