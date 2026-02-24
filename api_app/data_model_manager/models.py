import json
import logging
from typing import Dict, Type, Union

from django.contrib.contenttypes.fields import GenericRelation
from django.contrib.contenttypes.models import ContentType
from django.contrib.postgres import fields as pg_fields
from django.contrib.postgres.fields import ArrayField
from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models
from django.db.models import ForeignKey, ManyToManyField, PositiveIntegerField
from django.forms import JSONField
from django.utils.timezone import now
from rest_framework.serializers import ModelSerializer

from api_app.data_model_manager.enums import (
    DataModelEvaluations,
    DataModelKillChainPhases,
    DataModelTags,
    SignatureProviderChoices,
)
from api_app.data_model_manager.fields import LowercaseCharField, SetField
from api_app.data_model_manager.queryset import BaseDataModelQuerySet
from certego_saas.apps.user.models import User

logger = logging.getLogger(__name__)


class IETFReport(models.Model):
    rrname = LowercaseCharField(max_length=100)
    rrtype = LowercaseCharField(max_length=100)
    rdata = pg_fields.ArrayField(LowercaseCharField(max_length=100))
    time_first = models.DateTimeField()
    time_last = models.DateTimeField()

    class Meta:
        unique_together = ("rrname", "rrtype", "rdata")

    def __str__(self):
        return json.dumps(
            {
                "rrname": self.rrname,
                "rrtype": self.rrtype,
                "rdata": self.rdata,
                "time_first": self.time_first.strftime("%Y-%m-%d %H:%M:%S"),
                "time_last": self.time_last.strftime("%Y-%m-%d %H:%M:%S"),
            }
        )


class Signature(models.Model):
    provider = LowercaseCharField(max_length=100)
    url = models.URLField(default="", blank=True)
    score = models.PositiveIntegerField(default=0)
    signature = models.JSONField()

    PROVIDERS = SignatureProviderChoices

    def __str__(self):
        return f"{self.provider}: {json.dumps(self.signature)}"


class BaseDataModel(models.Model):
    objects = BaseDataModelQuerySet.as_manager()
    evaluation = LowercaseCharField(
        max_length=100,
        null=True,
        blank=True,
        default=None,
        choices=DataModelEvaluations.choices,
    )
    reliability = PositiveIntegerField(
        validators=[MinValueValidator(0), MaxValueValidator(10)], default=5
    )
    kill_chain_phase = LowercaseCharField(
        default=None,
        null=True,
        blank=True,
        choices=DataModelKillChainPhases.choices,
        max_length=100,
    )
    external_references = SetField(
        models.URLField(),
        blank=True,
        default=list,
    )
    related_threats = SetField(
        LowercaseCharField(max_length=100), default=list, blank=True
    )  # threats/related_threats, used as a pointer to other IOCs
    tags = SetField(
        LowercaseCharField(max_length=100), null=True, blank=True, default=None
    )
    malware_family = LowercaseCharField(
        max_length=100, null=True, blank=True, default=None
    )
    additional_info = models.JSONField(
        default=dict
    )  # field for additional information related to a specific analyzer
    date = models.DateTimeField(default=now)
    analyzers_report = GenericRelation(
        to="analyzers_manager.AnalyzerReport",
        object_id_field="data_model_object_id",
        content_type_field="data_model_content_type",
    )
    jobs = GenericRelation(
        to="api_app.Job",
        object_id_field="data_model_object_id",
        content_type_field="data_model_content_type",
    )

    user_events = GenericRelation(
        to="user_events_manager.UserAnalyzableEvent",
        object_id_field="data_model_object_id",
        content_type_field="data_model_content_type",
    )

    TAGS = DataModelTags

    EVALUATIONS = DataModelEvaluations

    class Meta:
        abstract = True
        indexes = [
            models.Index(fields=["date"]),
        ]

    @property
    def owner(self) -> User:
        if self.analyzers_report.exists():
            return self.analyzers_report.first().user
        elif self.jobs.exists():
            return self.jobs.first().user

    def merge(
        self, other: Union["BaseDataModel", Dict], append: bool = True
    ) -> "BaseDataModel":
        if not self.pk:
            raise ValueError("Unable to merge a model that was not saved.")
        if not isinstance(other, (self.__class__, dict)):
            raise TypeError(f"Different class between {self} and {type(other)}")
        for field_name, field in self.get_fields().items():
            if field_name == "id":
                continue
            result_attr = getattr(self, field_name)
            if isinstance(other, dict):
                try:
                    other_attr = other[field_name]
                except KeyError:
                    continue
            else:
                other_attr = getattr(other, field_name, None)
            if not other_attr:
                continue
            if append:
                if isinstance(field, ArrayField):
                    if not result_attr:
                        result_attr = []
                    result_attr.extend(other_attr)
                elif isinstance(field, (JSONField, SetField)):
                    if not result_attr:
                        result_attr = {}
                    result_attr |= other_attr
                elif isinstance(field, ManyToManyField):
                    result_attr.add(*other_attr.values_list("pk", flat=True))
                    continue
                elif isinstance(field, ForeignKey):
                    if isinstance(other_attr, dict):
                        other_attr = field.related_model.objects.get_or_create(
                            **other_attr
                        )
                    elif isinstance(other_attr, models.Model):
                        pass
                    else:
                        logger.error(
                            f"Field {field_name} has wrong type with value {other_attr}"
                        )
                        continue
                    result_attr = other_attr
                else:
                    result_attr = other_attr
            else:
                result_attr = other_attr
            setattr(self, field_name, result_attr)
        self.save()
        return self

    def __sub__(self, other: "BaseDataModel") -> "BaseDataModel":
        from deepdiff import DeepDiff

        if not isinstance(other, BaseDataModel):
            raise TypeError(f"Different class between {self} and {type(other)}")
        dict1 = self.serialize()
        dict2 = other.serialize()
        result = DeepDiff(
            dict1,
            dict2,
            ignore_order=True,
            verbose_level=1,
            exclude_paths=["id", "analyzers_report", "jobs", "date"],
        )

        new = self.__class__.objects.create()
        return new.merge(result)

    @classmethod
    def get_content_type(cls) -> ContentType:
        return ContentType.objects.get_for_model(model=cls)

    @classmethod
    def get_fields(cls) -> Dict:
        return {
            field.name: field for field in cls._meta.fields + cls._meta.many_to_many
        }

    @classmethod
    def get_serializer(cls) -> Type[ModelSerializer]:
        raise NotImplementedError()

    def serialize(self) -> Dict:
        return self.get_serializer()(self, read_only=True).data


class DomainDataModel(BaseDataModel):
    ietf_report = models.ManyToManyField(IETFReport, related_name="domains")  # pdns
    rank = models.IntegerField(null=True, blank=True, default=None)  # Tranco
    resolutions = SetField(LowercaseCharField(max_length=100), default=list)

    @classmethod
    def get_serializer(cls) -> Type[ModelSerializer]:
        from api_app.data_model_manager.serializers import DomainDataModelSerializer

        return DomainDataModelSerializer


class IPDataModel(BaseDataModel):
    ietf_report = models.ManyToManyField(IETFReport, related_name="ips")  # pdns
    asn = models.IntegerField(
        null=True, blank=True, default=None
    )  # BGPRanking, MaxMind
    asn_rank = models.DecimalField(
        null=True, blank=True, default=None, decimal_places=20, max_digits=21
    )  # BGPRanking
    certificates = models.JSONField(null=True, blank=True, default=None)  # CIRCL_PSSL
    org_name = LowercaseCharField(
        max_length=100, null=True, blank=True, default=None
    )  # GreyNoise
    country_code = LowercaseCharField(
        max_length=100, null=True, blank=True, default=None
    )  # MaxMind, AbuseIPDB
    registered_country_code = LowercaseCharField(
        max_length=100, null=True, blank=True, default=None
    )  # MaxMind, AbuseIPDB
    isp = LowercaseCharField(max_length=100, null=True, blank=True, default=None)
    resolutions = SetField(models.URLField(), default=list)
    # AbuseIPDB
    # additional_info
    # behavior = LowercaseCharField(max_length=100, null=True)  # Crowdsec
    # noise = models.BooleanField(null=True)  # GreyNoise
    # riot = models.BooleanField(null=True)  # GreyNoise

    @classmethod
    def get_serializer(cls) -> Type[ModelSerializer]:
        from api_app.data_model_manager.serializers import IPDataModelSerializer

        return IPDataModelSerializer


class FileDataModel(BaseDataModel):
    signatures = models.ManyToManyField(
        Signature, related_name="files"
    )  # ClamAvFileAnalyzer,
    # MalwareBazaarFileAnalyzer (signatures/yara_rules), Yara (report.list_el.match)
    # Yaraify (report.data.tasks.static_result)
    comments = SetField(
        LowercaseCharField(max_length=100), default=list, blank=True
    )  # MalwareBazaarFileAnalyzer,
    # VirusTotalV3FileAnalyzer (data.relationships.comments)
    file_information = models.JSONField(
        default=dict, blank=True
    )  # MalwareBazaarFileAnalyzer, OneNoteInfo (files),
    # QuarkEngineAPK (crimes.confidence, threat_level, total_score)
    # RtfInfo (exploit_equation_editor, exploit_ole2link_vuln)
    stats = models.JSONField(default=dict, blank=True)  # PdfInfo (peepdf_stats)
    # additional_info
    # compromised_hosts = pg_fields.ArrayField(
    #   LowercaseCharField(max_length=100), null=True
    # )  # HybridAnalysisFileAnalyzer
    # pdfid_reports = models.JSONField(null=True)  # PdfInfo
    # imphash = LowercaseCharField(max_length=100, null=True)  # PeInfo
    # type = LowercaseCharField(max_length=100, null=True)  # PeInfo

    @classmethod
    def get_serializer(cls) -> Type[ModelSerializer]:
        from api_app.data_model_manager.serializers import FileDataModelSerializer

        return FileDataModelSerializer
