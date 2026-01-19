import logging
from typing import Type, Union

from django.core.exceptions import ValidationError
from django.db import models
from django.db.models import Q
from django.utils.timezone import now

from api_app.analyzables_manager.queryset import AnalyzableQuerySet
from api_app.choices import Classification
from api_app.data_model_manager.models import BaseDataModel
from api_app.data_model_manager.queryset import BaseDataModelQuerySet
from api_app.defaults import file_directory_path
from api_app.helpers import calculate_md5, calculate_sha1, calculate_sha256
from certego_saas.models import User

logger = logging.getLogger(__name__)


class Analyzable(models.Model):
    name = models.CharField(max_length=255)
    discovery_date = models.DateTimeField(default=now)
    md5 = models.CharField(max_length=255, unique=True, editable=False)
    sha256 = models.CharField(max_length=255, unique=True, editable=False)
    sha1 = models.CharField(max_length=255, unique=True, editable=False)
    classification = models.CharField(max_length=100, choices=Classification.choices)
    mimetype = models.CharField(max_length=80, blank=True, null=True, default=None)
    file = models.FileField(
        upload_to=file_directory_path, null=True, blank=True, default=None
    )
    CLASSIFICATIONS = Classification
    objects = AnalyzableQuerySet.as_manager()

    class Meta:
        indexes = [
            models.Index(fields=["name"]),
            models.Index(fields=["classification"]),
            models.Index(fields=["mimetype"]),
        ]

    def __str__(self):
        return self.name

    @property
    def analyzed_object(self):
        return self.file if self.is_sample else self.name

    @property
    def is_sample(self) -> bool:
        return self.classification == Classification.FILE.value

    def get_all_user_events_data_model(
        self, user: User = None
    ) -> BaseDataModelQuerySet:
        query = Q(user_events__analyzable=self)
        if user:
            query &= Q(
                pk__in=self.user_events.visible_for_user(user).values_list(
                    "data_model_object_id", flat=True
                )
            )
        if self.classification in [
            Classification.URL.value,
            Classification.DOMAIN.value,
        ]:
            query2 = Q(domain_wildcard_events__analyzables=self)
            if user:
                query2 &= Q(
                    pk__in=self.user_domain_wildcard_events.visible_for_user(
                        user
                    ).values_list("data_model__pk", flat=True)
                )
            query |= query2
        elif self.classification == Classification.IP.value:
            query2 = Q(ip_wildcard_events__analyzables=self)
            if user:
                query2 &= Q(
                    pk__in=self.user_ip_wildcard_events.visible_for_user(
                        user
                    ).values_list("data_model__pk", flat=True)
                )
            query |= query2
        logger.debug(f"{query=}")
        return self.get_data_model_class().objects.filter(query)

    def get_data_model_class(self) -> Type[BaseDataModel]:
        return self.CLASSIFICATIONS.get_data_model_class(self.classification)

    def _set_hashes(self, value: Union[str, bytes]):
        if isinstance(value, str):
            value = value.encode("utf-8")
        if not self.md5:
            self.md5 = calculate_md5(value)
        if not self.sha256:
            self.sha256 = calculate_sha256(value)
        if not self.sha1:
            self.sha1 = calculate_sha1(value)

    def clean(self):
        if self.file:
            self.classification = Classification.FILE.value
        else:
            self.classification = Classification.calculate_observable(self.name)
        if self.classification == Classification.FILE.value:
            from api_app.analyzers_manager.models import MimeTypes

            if not self.file:
                raise ValidationError("File must be set for samples")
            content = self.read()
            if not self.mimetype:
                self.mimetype = MimeTypes.calculate(content, self.name)
        else:
            if self.mimetype or self.file:
                raise ValidationError(
                    "Mimetype and file must not be set for observables"
                )
            content = self.name
        self._set_hashes(content)

    def read(self) -> bytes:
        if self.classification == Classification.FILE.value:
            self.file.seek(0)
            return self.file.read()
