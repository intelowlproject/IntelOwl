from typing import Type, Union

from django.core.exceptions import ValidationError
from django.db import models
from django.db.models import Q
from django.utils.timezone import now

from api_app.analyzables_manager.queryset import AnalyzableQuerySet
from api_app.choices import Classification
from api_app.data_model_manager.models import (
    BaseDataModel,
    DomainDataModel,
    FileDataModel,
    IPDataModel,
)
from api_app.data_model_manager.queryset import BaseDataModelQuerySet
from api_app.defaults import file_directory_path
from api_app.helpers import calculate_md5, calculate_sha1, calculate_sha256


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

    def get_all_user_events_data_model(self) -> BaseDataModelQuerySet:
        query = Q(user_events__analyzable=self)
        if self.classification in [
            Classification.URL.value,
            Classification.DOMAIN.value,
        ]:
            query |= Q(domain_wildcard_events__analyzables=self)
        elif self.classification == Classification.IP.value:
            query |= Q(ip_wildcard_events__analyzables=self)
        return self.get_data_model_class().objects.filter(query)

    def get_data_model_class(self) -> Type[BaseDataModel]:
        if self.classification == Classification.IP.value:
            return IPDataModel
        elif self.classification in [
            Classification.URL.value,
            Classification.DOMAIN.value,
        ]:
            return DomainDataModel
        elif self.classification in [
            Classification.HASH.value,
            Classification.FILE.value,
        ]:
            return FileDataModel
        else:
            raise NotImplementedError()

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
