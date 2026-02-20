import uuid
from typing import Generator

from celery import group
from celery.canvas import Signature
from django.conf import settings
from django.contrib.postgres.fields import ArrayField
from django.db import models
from solo.models import SingletonModel

from api_app.choices import Classification
from api_app.engines_manager.validators import validate_engine_module
from api_app.models import Job
from intel_owl.celery import get_queue_name


class EngineConfig(SingletonModel):
    modules = ArrayField(
        models.CharField(max_length=255, null=False, blank=False, validators=[validate_engine_module]),
        blank=True,
        default=list,
        help_text="List of modules used by the engine. Each module has syntax `name_file.name_class`",
    )

    def get_modules_signatures(self, job) -> Generator[Signature, None, None]:
        from api_app.engines_manager.tasks import execute_engine_module

        for path in self.modules:
            yield execute_engine_module.signature(
                args=[job.pk, f"{settings.BASE_ENGINE_MODULES_PYTHON_PATH}.{path}"],
                queue=get_queue_name(settings.DEFAULT_QUEUE),
                immutable=True,
                MessageGroupId=str(uuid.uuid4()),
                priority=job.priority,
            )

    def run(self, job: Job) -> None:
        from django.db import transaction

        from api_app.data_model_manager.models import BaseDataModel

        if job.analyzable.classification == Classification.GENERIC:
            # at the moment, since there are no datamodels for the generic, we are completely skipping an evaluation
            return

        with transaction.atomic():
            data_model_result: BaseDataModel = job.get_analyzers_data_models().merge(append=True)
            previous_data_model = job.data_model
            job.data_model = data_model_result
            job.save()
            if previous_data_model:
                previous_data_model.delete()

        runner = group(list(self.get_modules_signatures(job)))
        runner.apply_async(
            queue=get_queue_name(settings.DEFAULT_QUEUE),
            immutable=True,
            MessageGroupId=str(uuid.uuid4()),
            priority=10,
        )
