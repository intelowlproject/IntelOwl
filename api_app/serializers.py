# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import copy
import datetime
import ipaddress
import json
import logging
import re
import uuid
from typing import Any, Dict, Generator, List, Union

import django.core.exceptions
from django.conf import settings
from django.core.cache import cache
from django.db.models import Q, QuerySet
from django.http import QueryDict
from django.utils.timezone import now
from django_celery_beat.models import CrontabSchedule, PeriodicTask
from durin.serializers import UserSerializer
from rest_framework import serializers as rfs
from rest_framework.exceptions import ValidationError
from rest_framework.fields import Field, SerializerMethodField, empty
from rest_framework.serializers import ModelSerializer

from certego_saas.apps.organization.organization import Organization
from certego_saas.apps.organization.permissions import IsObjectOwnerOrSameOrgPermission
from certego_saas.apps.user.models import User
from intel_owl.celery import get_queue_name

from .analyzers_manager.constants import ObservableTypes, TypeChoices
from .analyzers_manager.models import AnalyzerConfig, MimeTypes
from .choices import TLP, ScanMode
from .connectors_manager.exceptions import NotRunnableConnector
from .connectors_manager.models import ConnectorConfig
from .defaults import default_runtime
from .helpers import calculate_md5, gen_random_colorhex
from .ingestors_manager.models import IngestorConfig
from .interfaces import OwnershipAbstractModel
from .models import (
    AbstractReport,
    Comment,
    Job,
    Parameter,
    PluginConfig,
    PythonConfig,
    PythonModule,
    Tag,
)
from .playbooks_manager.models import PlaybookConfig
from .visualizers_manager.models import VisualizerConfig

logger = logging.getLogger(__name__)


class TagSerializer(rfs.ModelSerializer):
    class Meta:
        model = Tag
        fields = rfs.ALL_FIELDS


class JobRecentScanSerializer(rfs.ModelSerializer):
    playbook = rfs.CharField(
        source="playbook_to_execute.name", allow_null=True, read_only=True
    )
    user = rfs.CharField(source="user.username", allow_null=False, read_only=True)
    importance = rfs.IntegerField(allow_null=True, read_only=True)

    class Meta:
        model = Job
        fields = [
            "playbook",
            "pk",
            "tlp",
            "user",
            "importance",
            "observable_name",
            "file_name",
            "finished_analysis_time",
        ]


class _AbstractJobViewSerializer(rfs.ModelSerializer):
    """
    Base Serializer for ``Job`` model's ``retrieve()`` and ``list()``.
    """

    user = UserSerializer()
    tags = TagSerializer(many=True, read_only=True)


class _AbstractJobCreateSerializer(rfs.ModelSerializer):
    """
    Base Serializer for ``Job`` model's ``create()``.
    """

    class Meta:
        fields = (
            "id",
            "user",
            "is_sample",
            "tlp",
            "runtime_configuration",
            "analyzers_requested",
            "connectors_requested",
            "playbook_requested",
            "tags_labels",
            "scan_mode",
            "scan_check_time",
        )

    md5 = rfs.HiddenField(default=None)
    is_sample = rfs.HiddenField(write_only=True, default=False)
    user = rfs.HiddenField(default=rfs.CurrentUserDefault())
    scan_mode = rfs.ChoiceField(
        choices=ScanMode.choices,
        required=False,
    )
    scan_check_time = rfs.DurationField(required=False, allow_null=True)

    tags_labels = rfs.ListField(
        child=rfs.CharField(required=True), default=list, required=False
    )
    runtime_configuration = rfs.JSONField(required=False, write_only=True)
    tlp = rfs.ChoiceField(choices=TLP.values + ["WHITE"], required=False)

    connectors_requested = rfs.PrimaryKeyRelatedField(
        queryset=ConnectorConfig.objects.all(),
        many=True,
        default=ConnectorConfig.objects.none(),
    )
    analyzers_requested = rfs.PrimaryKeyRelatedField(
        queryset=AnalyzerConfig.objects.all(),
        many=True,
        default=AnalyzerConfig.objects.none(),
    )

    def validate_runtime_configuration(self, runtime_config: Dict):
        from api_app.validators import validate_runtime_configuration

        if not runtime_config:
            runtime_config = default_runtime()
        try:
            validate_runtime_configuration(runtime_config)
        except django.core.exceptions.ValidationError as e:
            logger.info(e, stack_info=True)
            raise ValidationError({"detail": "Runtime Configuration Validation Failed"})
        return runtime_config

    def validate_tags_labels(self, tags_labels):
        for label in tags_labels:
            yield Tag.objects.get_or_create(
                label=label, defaults={"color": gen_random_colorhex()}
            )[0]

    def validate_tlp(self, tlp: str):
        if tlp == "WHITE":
            return TLP.CLEAR.value
        return tlp

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.filter_warnings = []

    def run_validation(self, data=empty):
        result = super().run_validation(data=data)
        self.filter_warnings.clear()
        return result

    @staticmethod
    def set_default_value_from_playbook(attrs: Dict) -> None:
        playbook = attrs["playbook_requested"]
        # we are changing attrs in place
        for attribute in [
            "scan_mode",
            "scan_check_time",
            "tlp",
            "runtime_configuration",
        ]:
            if attribute not in attrs:
                attrs[attribute] = getattr(playbook, attribute)

    def validate(self, attrs: dict) -> dict:
        if attrs.get("playbook_requested"):
            self.set_default_value_from_playbook(attrs)
        if "tlp" not in attrs:
            attrs["tlp"] = TLP.CLEAR.value
        if "scan_mode" not in attrs:
            attrs["scan_mode"] = ScanMode.CHECK_PREVIOUS_ANALYSIS.value
        if attrs.get(
            "scan_mode"
        ) == ScanMode.CHECK_PREVIOUS_ANALYSIS.value and not attrs.get(
            "scan_check_time"
        ):
            attrs["scan_check_time"] = datetime.timedelta(hours=24)
        elif attrs.get("scan_mode") == ScanMode.FORCE_NEW_ANALYSIS.value:
            attrs["scan_check_time"] = None
        attrs = super().validate(attrs)
        if playbook := attrs.get("playbook_requested", None):
            playbook: PlaybookConfig
            if attrs.get("analyzers_requested", []) or attrs.get(
                "connectors_requested", []
            ):
                raise ValidationError(
                    {"detail": "You can't specify a playbook and plugins together"}
                )
            if playbook.disabled:
                raise ValidationError(
                    {"detail": "No playbooks can be run after filtering."}
                )
            attrs["playbook_to_execute"] = playbook
            attrs["analyzers_requested"] = list(playbook.analyzers.all())
            attrs["connectors_requested"] = list(playbook.connectors.all())
            attrs["tags_labels"] = list(attrs.get("tags_labels", [])) + list(
                playbook.tags.all()
            )

        attrs["analyzers_to_execute"] = self.set_analyzers_to_execute(**attrs)
        attrs["connectors_to_execute"] = self.set_connectors_to_execute(**attrs)
        attrs["visualizers_to_execute"] = self.set_visualizers_to_execute(**attrs)
        attrs["warnings"] = list(self.filter_warnings)
        attrs["tags"] = attrs.pop("tags_labels", [])
        return attrs

    def set_visualizers_to_execute(
        self,
        tlp: str,
        playbook_requested: PlaybookConfig = None,
        **kwargs,
    ) -> List[VisualizerConfig]:
        if playbook_requested:
            visualizers = VisualizerConfig.objects.filter(
                playbooks__in=[playbook_requested]
            )
        else:
            visualizers = []
        return list(self.plugins_to_execute(tlp, visualizers))

    def set_connectors_to_execute(
        self, connectors_requested: List[ConnectorConfig], tlp: str, **kwargs
    ) -> List[ConnectorConfig]:
        return list(self.plugins_to_execute(tlp, connectors_requested))

    def set_analyzers_to_execute(
        self, analyzers_requested: List[AnalyzerConfig], tlp: str, **kwargs
    ) -> List[AnalyzerConfig]:
        analyzers_executed = list(self.plugins_to_execute(tlp, analyzers_requested))
        if not analyzers_executed:
            warnings = "\n".join(self.filter_warnings)
            raise ValidationError(
                {"detail": f"No Analyzers can be run after filtering:\n{warnings}"}
            )
        return analyzers_executed

    def plugins_to_execute(
        self,
        tlp,
        plugins_requested: Union[
            List[Union[AnalyzerConfig, ConnectorConfig, VisualizerConfig]], QuerySet
        ],
    ) -> Generator[
        Union[AnalyzerConfig, ConnectorConfig, VisualizerConfig], None, None
    ]:
        if not plugins_requested:
            return
        if isinstance(plugins_requested, QuerySet):
            qs = plugins_requested
        else:
            qs = plugins_requested[0].__class__.objects.filter(
                pk__in=[plugin.pk for plugin in plugins_requested]
            )
        for plugin_config in qs.annotate_runnable(self.context["request"].user):
            try:
                if not plugin_config.runnable:
                    raise NotRunnableConnector(
                        f"{plugin_config.name} won't run: is disabled or not configured"
                    )
                try:
                    if (
                        TLP[tlp] > TLP[plugin_config.maximum_tlp]
                    ):  # check if job's tlp allows running
                        # e.g. if connector_tlp is GREEN(1),
                        # run for job_tlp CLEAR(0) & GREEN(1) only
                        raise NotRunnableConnector(
                            f"{plugin_config.name} won't run because "
                            f"job.tlp is '{tlp}') while plugin"
                            f" maximum_tlp ('{plugin_config.maximum_tlp}')"
                        )
                except AttributeError:
                    # in case the plugin does not have maximum_tlp:
                    pass
            except NotRunnableConnector as e:
                self.filter_warnings.append(str(e))
                logger.info(e)
            else:
                yield plugin_config

    def check_previous_jobs(self, validated_data: Dict) -> Job:
        logger.info("Checking previous jobs")
        if not validated_data["scan_check_time"]:
            raise ValidationError("Scan check time can't be null")
        status_to_exclude = [Job.Status.KILLED, Job.Status.FAILED]
        if not validated_data.get("playbook_to_execute", None):
            status_to_exclude.append(Job.Status.REPORTED_WITH_FAILS)
        qs = (
            self.Meta.model.objects.visible_for_user(self.context["request"].user)
            .filter(
                received_request_time__gte=now() - validated_data["scan_check_time"]
            )
            .filter(Q(md5=validated_data["md5"]))
        )
        for analyzer in validated_data.get("analyzers_to_execute", []):
            qs = qs.filter(analyzers_requested__in=[analyzer])
        for connector in validated_data.get("connectors_to_execute", []):
            qs = qs.filter(connectors_requested__in=[connector])
        for visualizer in validated_data.get("visualizers_to_execute", []):
            qs = qs.filter(visualizers_to_execute__in=[visualizer])

        return qs.exclude(status__in=status_to_exclude).latest("received_request_time")

    def create(self, validated_data: Dict) -> Job:
        warnings = validated_data.pop("warnings")
        send_task = validated_data.pop("send_task", False)
        if validated_data["scan_mode"] == ScanMode.CHECK_PREVIOUS_ANALYSIS.value:
            try:
                return self.check_previous_jobs(validated_data)
            except self.Meta.model.DoesNotExist:
                job = super().create(validated_data)
        else:
            job = super().create(validated_data)
        job.warnings = warnings
        job.save()
        logger.info(f"Job {job.pk} created")
        if send_task:
            from intel_owl.tasks import job_pipeline

            logger.info(f"Sending task for job {job.pk}")
            job_pipeline.apply_async(
                args=[job.pk],
                queue=get_queue_name(settings.DEFAULT_QUEUE),
                MessageGroupId=str(uuid.uuid4()),
            )

        return job


class CommentSerializer(rfs.ModelSerializer):
    """
    Used for ``create()``
    """

    class Meta:
        model = Comment
        fields = ("id", "content", "created_at", "user", "job_id")

    user = UserSerializer(read_only=True)
    job_id = rfs.PrimaryKeyRelatedField(
        queryset=Job.objects.all(), write_only=True, source="job"
    )

    def validate(self, attrs: dict) -> dict:
        attrs = super().validate(attrs)

        user = self.context["request"].user
        job = attrs.get("job")
        try:
            Job.objects.visible_for_user(user).get(pk=job.pk)
        except Job.DoesNotExist:
            raise ValidationError(
                {"detail": f"You have no permission to comment on job {job.pk}"}
            )
        return attrs

    def create(self, validated_data: dict) -> Comment:
        validated_data["user"] = self.context["request"].user
        return super().create(validated_data)


class JobListSerializer(_AbstractJobViewSerializer):
    """
    Used for ``list()``.
    """

    class Meta:
        model = Job
        exclude = (
            "file",
            "errors",
        )

    pivots_to_execute = rfs.SerializerMethodField(read_only=True)

    def get_pivots_to_execute(self, obj: Job):
        return obj.pivots_to_execute.all().values_list("name", flat=True)


class JobSerializer(_AbstractJobViewSerializer):
    """
    Used for ``retrieve()``
    """

    class Meta:
        model = Job
        exclude = ("file",)

    comments = CommentSerializer(many=True, read_only=True)
    pivots_to_execute = rfs.SerializerMethodField(read_only=True)
    permissions = rfs.SerializerMethodField()

    def get_pivots_to_execute(self, obj: Job):
        return obj.pivots_to_execute.all().values_list("name", flat=True)

    def get_fields(self):
        # this method override is required for a cyclic import
        from api_app.analyzers_manager.serializers import AnalyzerReportSerializer
        from api_app.connectors_manager.serializers import ConnectorReportSerializer
        from api_app.pivots_manager.serializers import PivotReportSerializer
        from api_app.visualizers_manager.serializers import VisualizerReportSerializer

        for field, serializer in [
            ("analyzer", AnalyzerReportSerializer),
            ("connector", ConnectorReportSerializer),
            ("pivot", PivotReportSerializer),
            ("visualizer", VisualizerReportSerializer),
        ]:
            self._declared_fields[f"{field}_reports"] = serializer(
                many=True, read_only=True, source=f"{field}reports"
            )
        return super().get_fields()

    def get_permissions(self, obj: Job) -> Dict[str, bool]:
        request = self.context.get("request", None)
        view = self.context.get("view", None)
        if request and view:
            has_perm = IsObjectOwnerOrSameOrgPermission().has_object_permission(
                request, view, obj
            )
            return {
                "kill": has_perm,
                "delete": has_perm,
                "plugin_actions": has_perm,
            }
        return {}


class MultipleFileAnalysisSerializer(rfs.ListSerializer):
    """
    ``Job`` model's serializer for Multiple File Analysis.
    Used for ``create()``.
    """

    def update(self, instance, validated_data):
        raise NotImplementedError("This serializer does not support update().")

    files = rfs.ListField(child=rfs.FileField(required=True), required=True)

    file_names = rfs.ListField(child=rfs.CharField(required=True), required=True)

    file_mimetypes = rfs.ListField(
        child=rfs.CharField(required=True, allow_blank=True), required=False
    )

    def to_internal_value(self, data: QueryDict):
        ret = []
        errors = []
        if not isinstance(data, QueryDict):
            data_to_check = QueryDict(mutable=True)
            data_to_check.update(data)
        else:
            data_to_check = data
        if data_to_check.getlist("file_names", []) and len(
            data_to_check.getlist("file_names")
        ) != len(data_to_check.getlist("files")):
            raise ValidationError(
                {"detail": "file_names and files must have the same length."}
            )

        for index, file in enumerate(data_to_check.getlist("files")):
            # `deepcopy` here ensures that this code doesn't
            # break even if new fields are added in future
            item = data_to_check.copy()

            item["file"] = file
            if data_to_check.getlist("file_names", []):
                item["file_name"] = data_to_check.getlist("file_names")[index]
            if data_to_check.get("file_mimetypes", []):
                item["file_mimetype"] = data_to_check["file_mimetypes"][index]
            try:
                validated = self.child.run_validation(item)
            except ValidationError as exc:
                errors.append(exc.detail)
            else:
                ret.append(validated)

        if any(errors):
            raise ValidationError({"detail": errors})

        return ret


class MultiplePlaybooksMultipleFileAnalysisSerializer(MultipleFileAnalysisSerializer):
    playbooks_requested = rfs.PrimaryKeyRelatedField(
        queryset=PlaybookConfig.objects.all(), many=True
    )

    def to_internal_value(self, data):
        ret = []
        playbook_requested = data.pop("playbooks_requested", [None])
        # in case we have only one Playbook (multi-analysis Playbook is deprecated)
        # we do not need to do a deepcopy which is very costly in terms of RAM
        # and could trigger 500 errors for files bigger than 2.5MB
        # see: https://docs.djangoproject.com/en/4.2/ref/settings
        # /#std:setting-FILE_UPLOAD_MAX_MEMORY_SIZE
        if len(playbook_requested) == 1:
            results = self._generate_result(data, playbook_requested[0])
            ret.extend(results)
        else:
            for playbook in playbook_requested:
                item = copy.deepcopy(data)
                results = self._generate_result(item, playbook)
                ret.extend(results)
        data["playbooks_requested"] = playbook_requested
        return ret

    def _generate_result(self, data, playbook):
        data["playbook_requested"] = playbook
        return super().to_internal_value(data)


class FileAnalysisSerializer(_AbstractJobCreateSerializer):
    """
    ``Job`` model's serializer for File Analysis.
    Used for ``create()``.
    """

    file = rfs.FileField(required=True)
    file_name = rfs.CharField(required=False)
    file_mimetype = rfs.CharField(required=False)
    is_sample = rfs.HiddenField(write_only=True, default=True)

    class Meta:
        model = Job
        fields = _AbstractJobCreateSerializer.Meta.fields + (
            "file",
            "file_name",
            "file_mimetype",
        )

    @classmethod
    def many_init(cls, *args, **kwargs):
        # Instantiate the child serializer.
        data = kwargs["data"]
        kwargs["child"] = cls()
        if "playbooks_requested" in data:
            list_serializer_class = MultiplePlaybooksMultipleFileAnalysisSerializer
        else:
            list_serializer_class = MultipleFileAnalysisSerializer
        # Instantiate the parent list serializer.
        return list_serializer_class(*args, **kwargs)

    def validate(self, attrs: dict) -> dict:
        logger.debug(f"before attrs: {attrs}")
        # calculate ``file_mimetype``
        if "file_name" not in attrs:
            attrs["file_name"] = attrs["file"].name
        attrs["file_mimetype"] = MimeTypes.calculate(attrs["file"], attrs["file_name"])
        # calculate ``md5``
        file_obj = attrs["file"].file
        file_obj.seek(0)
        file_buffer = file_obj.read()
        attrs["md5"] = calculate_md5(file_buffer)
        attrs = super().validate(attrs)
        logger.debug(f"after attrs: {attrs}")
        return attrs

    def set_analyzers_to_execute(
        self,
        analyzers_requested: List[AnalyzerConfig],
        tlp: str,
        file_mimetype: str,
        file_name: str,
        **kwargs,
    ) -> List[AnalyzerConfig]:
        analyzers_to_execute = analyzers_requested.copy()

        # get values from serializer
        partially_filtered_analyzers_qs = AnalyzerConfig.objects.filter(
            pk__in=[config.pk for config in analyzers_to_execute]
        )
        if file_mimetype in [MimeTypes.ZIP1.value, MimeTypes.ZIP1.value]:
            EXCEL_OFFICE_FILES = r"\.[xl]\w{0,3}$"
            DOC_OFFICE_FILES = r"\.[doc]\w{0,3}$"
            if re.search(DOC_OFFICE_FILES, file_name):
                # its an excel file
                file_mimetype = MimeTypes.DOC.value
            elif re.search(EXCEL_OFFICE_FILES, file_name):
                # its an excel file
                file_mimetype = MimeTypes.EXCEL1.value
            else:
                # its an android file
                file_mimetype = MimeTypes.APK.value

        supported_query = (
            Q(
                supported_filetypes__len=0,
            )
            & ~Q(not_supported_filetypes__contains=[file_mimetype])
        ) | Q(supported_filetypes__contains=[file_mimetype])

        for analyzer in partially_filtered_analyzers_qs.exclude(
            Q(type=TypeChoices.FILE) & supported_query
        ):
            analyzers_to_execute.remove(analyzer)
            message = (
                f"{analyzer.name} won't be run "
                "because does not support the file mimetype."
            )
            logger.info(message)
            self.filter_warnings.append(message)
        return super().set_analyzers_to_execute(analyzers_to_execute, tlp)


class MultipleObservableAnalysisSerializer(rfs.ListSerializer):
    """
    ``Job`` model's serializer for Multiple Observable Analysis.
    Used for ``create()``.
    """

    observables = rfs.ListField(required=True)

    def update(self, instance, validated_data):
        raise NotImplementedError("This serializer does not support update().")

    def to_internal_value(self, data):
        ret = []
        errors = []
        observables = data.pop("observables", [])
        # TODO we could change the signature, but this means change frontend + clients
        for _, name in observables:
            # `deepcopy` here ensures that this code doesn't
            # break even if new fields are added in future
            item = copy.deepcopy(data)
            item["observable_name"] = name
            try:
                validated = self.child.run_validation(item)
            except ValidationError as exc:
                errors.append(exc.detail)
            else:
                ret.append(validated)
        data["observables"] = observables
        if any(errors):
            raise ValidationError({"detail": errors})
        return ret


class MultiplePlaybooksMultipleObservableAnalysisSerializer(
    MultipleObservableAnalysisSerializer
):
    playbooks_requested = rfs.PrimaryKeyRelatedField(
        queryset=PlaybookConfig.objects.all(), many=True
    )

    def to_internal_value(self, data):
        ret = []
        playbooks = data.pop("playbooks_requested", [None])
        for playbook in playbooks:
            item = copy.deepcopy(data)
            item["playbook_requested"] = playbook
            results = super().to_internal_value(item)
            ret.extend(results)
        data["playbooks_requested"] = playbooks
        return ret


class ObservableAnalysisSerializer(_AbstractJobCreateSerializer):
    """
    ``Job`` model's serializer for Observable Analysis.
    Used for ``create()``.
    """

    observable_name = rfs.CharField(required=True)
    observable_classification = rfs.CharField(required=False)
    is_sample = rfs.HiddenField(write_only=True, default=False)

    class Meta:
        model = Job
        fields = _AbstractJobCreateSerializer.Meta.fields + (
            "observable_name",
            "observable_classification",
        )

    @classmethod
    def many_init(cls, *args, **kwargs):
        # Instantiate the child serializer.
        data = kwargs["data"]
        kwargs["child"] = cls()
        if "playbooks_requested" in data:
            list_serializer_class = (
                MultiplePlaybooksMultipleObservableAnalysisSerializer
            )
        else:
            list_serializer_class = MultipleObservableAnalysisSerializer
        # Instantiate the parent list serializer.
        return list_serializer_class(*args, **kwargs)

    def validate(self, attrs: dict) -> dict:
        logger.debug(f"before attrs: {attrs}")
        attrs["observable_name"] = self.defanged_values_removal(
            attrs["observable_name"]
        )
        # calculate ``observable_classification``
        if not attrs.get("observable_classification", None):
            attrs["observable_classification"] = ObservableTypes.calculate(
                attrs["observable_name"]
            )
        if attrs["observable_classification"] in [
            ObservableTypes.HASH,
            ObservableTypes.DOMAIN,
        ]:
            # force lowercase in ``observable_name``.
            # Ref: https://github.com/intelowlproject/IntelOwl/issues/658
            attrs["observable_name"] = attrs["observable_name"].lower()

        if attrs["observable_classification"] == ObservableTypes.IP.value:
            ip = ipaddress.ip_address(attrs["observable_name"])
            if ip.is_loopback:
                raise ValidationError({"detail": "Loopback address"})
            elif ip.is_private:
                raise ValidationError({"detail": "Private address"})
            elif ip.is_multicast:
                raise ValidationError({"detail": "Multicast address"})
            elif ip.is_link_local:
                raise ValidationError({"detail": "Local link address"})
            elif ip.is_reserved:
                raise ValidationError({"detail": "Reserved address"})

        # calculate ``md5``
        attrs["md5"] = calculate_md5(attrs["observable_name"].encode("utf-8"))
        attrs = super().validate(attrs)
        logger.debug(f"after attrs: {attrs}")
        return attrs

    @staticmethod
    def defanged_values_removal(value):
        if "\\" in value:
            value = value.replace("\\", "")
        if "]" in value:
            value = value.replace("]", "")
        if "[" in value:
            value = value.replace("[", "")
        # this is a trick done by spammers
        if "\n" in value:
            value = value.replace("\n", "")
        return value

    def set_analyzers_to_execute(
        self,
        analyzers_requested: List[AnalyzerConfig],
        tlp: str,
        observable_classification: str,
        **kwargs,
    ) -> List[AnalyzerConfig]:
        analyzers_to_execute = analyzers_requested.copy()

        partially_filtered_analyzers_qs = AnalyzerConfig.objects.filter(
            pk__in=[config.pk for config in analyzers_to_execute]
        )
        for analyzer in partially_filtered_analyzers_qs.exclude(
            type=TypeChoices.OBSERVABLE,
            observable_supported__contains=[observable_classification],
        ):
            analyzers_to_execute.remove(analyzer)
            message = (
                f"{analyzer.name} won't be run because"
                " it does not support the requested observable."
            )
            logger.info(message)
            self.filter_warnings.append(message)

        return super().set_analyzers_to_execute(analyzers_to_execute, tlp)


class JobEnvelopeSerializer(rfs.ListSerializer):
    @property
    def data(self):
        # this is to return a dict instead of a list
        return super(rfs.ListSerializer, self).data

    def to_internal_value(self, data):
        super().to_internal_value(data)

    def to_representation(self, data):
        results = super().to_representation(data)
        return {"results": results, "count": len(results)}


class JobResponseSerializer(rfs.ModelSerializer):
    STATUS_ACCEPTED = "accepted"
    STATUS_NOT_AVAILABLE = "not_available"

    job_id = rfs.IntegerField(source="pk")
    analyzers_running = rfs.PrimaryKeyRelatedField(
        read_only=True, source="analyzers_to_execute", many=True
    )
    connectors_running = rfs.PrimaryKeyRelatedField(
        read_only=True, source="connectors_to_execute", many=True
    )
    visualizers_running = rfs.PrimaryKeyRelatedField(
        read_only=True, source="visualizers_to_execute", many=True
    )
    playbook_running = rfs.PrimaryKeyRelatedField(
        read_only=True, source="playbook_to_execute"
    )

    class Meta:
        model = Job
        fields = [
            "job_id",
            "analyzers_running",
            "connectors_running",
            "visualizers_running",
            "playbook_running",
        ]
        extra_kwargs = {"warnings": {"read_only": True, "required": False}}
        list_serializer_class = JobEnvelopeSerializer

    def to_representation(self, instance: Job):
        result = super().to_representation(instance)
        result["status"] = self.STATUS_ACCEPTED
        result["already_exists"] = bool(
            instance.status in instance.Status.final_statuses()
        )
        return result

    def get_initial(self):
        initial = super().get_initial()
        initial.setdefault("status", self.STATUS_NOT_AVAILABLE)
        return initial


class JobAvailabilitySerializer(rfs.ModelSerializer):
    """
    Serializer for ask_analysis_availability
    """

    class Meta:
        model = Job
        fields = ["md5", "analyzers", "playbooks", "running_only", "minutes_ago"]

    md5 = rfs.CharField(max_length=128, required=True)
    analyzers = rfs.PrimaryKeyRelatedField(
        queryset=AnalyzerConfig.objects.all(), many=True, required=False
    )
    playbooks = rfs.PrimaryKeyRelatedField(
        queryset=PlaybookConfig.objects.all(), required=False, many=True
    )
    running_only = rfs.BooleanField(default=False, required=False)
    minutes_ago = rfs.IntegerField(default=None, required=False)

    def validate(self, attrs):
        attrs = super().validate(attrs)
        playbooks = attrs.get("playbooks", [])
        analyzers = attrs.get("analyzers", [])
        if not analyzers and not playbooks:
            attrs["analyzers"] = list(AnalyzerConfig.objects.all())
        elif len(playbooks) != 0 and len(analyzers) != 0:
            raise rfs.ValidationError(
                "Either only send the 'playbooks' parameter or the 'analyzers' one."
            )
        return attrs

    def create(self, validated_data):
        statuses_to_check = [Job.Status.RUNNING]

        if not validated_data["running_only"]:
            statuses_to_check.append(Job.Status.REPORTED_WITHOUT_FAILS)
            # since with playbook
            # it is expected behavior
            # for analyzers to often fail
            if validated_data.get("playbooks", []):
                statuses_to_check.append(Job.Status.REPORTED_WITH_FAILS)
        # this means that the user is trying to
        # check availability of the case where all
        # analyzers were run but no playbooks were
        # triggered.
        query = Q(md5=validated_data["md5"]) & Q(status__in=statuses_to_check)
        if validated_data.get("playbooks", []):
            query &= Q(playbook_requested__in=validated_data["playbooks"])
        else:
            analyzers = validated_data.get("analyzers", [])
            for analyzer in analyzers:
                query &= Q(analyzers_requested__in=[analyzer])
        # we want a job that has every analyzer requested
        if validated_data.get("minutes_ago", None):
            minutes_ago_time = now() - datetime.timedelta(
                minutes=validated_data["minutes_ago"]
            )
            query &= Q(received_request_time__gte=minutes_ago_time)

        last_job_for_md5 = (
            Job.objects.visible_for_user(self.context["request"].user)
            .filter(query)
            .only("pk")
            .latest("received_request_time")
        )
        return last_job_for_md5


class ModelWithOwnershipSerializer(rfs.ModelSerializer):
    class Meta:
        model = OwnershipAbstractModel
        fields = ("for_organization", "owner")
        abstract = True

    owner = rfs.HiddenField(default=rfs.CurrentUserDefault())
    organization = rfs.SlugRelatedField(
        queryset=Organization.objects.all(),
        required=False,
        allow_null=True,
        slug_field="name",
        write_only=True,
        default=None,
    )

    def validate(self, attrs):
        org = attrs.pop("organization", None)
        if org:
            # 1 - we are owner  OR
            # 2 - we are admin of the same org
            if org.owner == attrs["owner"] or (
                self.context["request"].user.has_membership()
                and self.context["request"].user.membership.organization.pk == org.pk
                and self.context["request"].user.membership.is_admin
            ):
                attrs["for_organization"] = True
            else:
                raise ValidationError(
                    {"detail": "You are not owner or admin of the organization"}
                )
        return super().validate(attrs)

    def to_representation(self, instance: OwnershipAbstractModel):
        result = super().to_representation(instance)
        result["owner"] = instance.owner.username if instance.owner else None
        return result


class PluginConfigSerializer(ModelWithOwnershipSerializer):
    class Meta:
        model = PluginConfig
        fields = (
            "attribute",
            "config_type",
            "type",
            "plugin_name",
            "value",
            "owner",
            "organization",
            "id",
        )

    class CustomValueField(rfs.JSONField):
        def to_internal_value(self, data):
            if not data:
                raise ValidationError({"detail": "Empty insertion"})
            logger.info(f"verifying that value {data} ({type(data)}) is JSON compliant")
            try:
                return json.loads(data)
            except json.JSONDecodeError:
                # this is to accept literal strings
                data = f'"{data}"'
                try:
                    return json.loads(data)
                except json.JSONDecodeError:
                    logger.info(f"value {data} ({type(data)}) raised ValidationError")
                    raise ValidationError({"detail": "Value is not JSON-compliant."})

        def get_attribute(self, instance: PluginConfig):
            # We return `redacted` when
            # 1) is a secret AND
            # 2) is a value for the organization AND
            # (NOR OPERATOR)
            # 3) we are not its owner OR
            # 4) we are not an admin of the same organization
            if (
                instance.is_secret()
                and instance.for_organization
                and not (
                    self.context["request"].user.pk == instance.owner.pk
                    or (
                        self.context["request"].user.has_membership()
                        and self.context["request"].user.membership.organization.pk
                        == instance.owner.membership.organization.pk
                        and self.context["request"].user.membership.is_admin
                    )
                )
            ):
                return "redacted"
            return super().get_attribute(instance)

        def to_representation(self, value):
            result = super().to_representation(value)
            if isinstance(result, (list, dict)):
                return json.dumps(result)
            return result

    type = rfs.ChoiceField(choices=["1", "2", "3", "4"])  # retrocompatibility
    config_type = rfs.ChoiceField(choices=["1", "2"])  # retrocompatibility
    attribute = rfs.CharField()
    plugin_name = rfs.CharField()
    value = CustomValueField()

    def validate_value_type(self, value: Any, parameter: Parameter):
        if type(value).__name__ != parameter.type:
            raise ValidationError(
                {
                    "detail": f"Value has type {type(value).__name__}"
                    f" instead of {parameter.type}"
                }
            )

    def validate(self, attrs):
        if self.partial:
            # we are in an update
            return attrs
        _value = attrs["value"]
        # retro compatibility
        _type = attrs.pop("type")
        _config_type = attrs.pop("config_type")
        _plugin_name = attrs.pop("plugin_name")
        _attribute = attrs.pop("attribute")
        if _type == "1":
            class_ = AnalyzerConfig
        elif _type == "2":
            class_ = ConnectorConfig
        elif _type == "3":
            class_ = VisualizerConfig
        elif _type == "4":
            class_ = IngestorConfig
        else:
            raise RuntimeError("Not configured")
        # we set the pointers allowing retro-compatibility from the frontend
        config = class_.objects.get(name=_plugin_name)
        parameter = config.parameters.get(
            name=_attribute, is_secret=_config_type == "2"
        )
        self.validate_value_type(_value, parameter)

        attrs["parameter"] = parameter
        attrs[class_.snake_case_name] = config
        return super().validate(attrs)

    def update(self, instance, validated_data):
        self.validate_value_type(validated_data["value"], instance.parameter)
        return super().update(instance, validated_data)

    def to_representation(self, instance: PluginConfig):
        result = super().to_representation(instance)
        result["organization"] = (
            instance.organization.name if instance.organization is not None else None
        )
        return result


class ParamListSerializer(rfs.ListSerializer):
    @property
    def data(self):
        # this is to return a dict instead of a list
        return super(rfs.ListSerializer, self).data

    def to_representation(self, data):
        result = super().to_representation(data)
        return {elem.pop("name"): elem for elem in result}


class ParameterSerializer(rfs.ModelSerializer):
    value = SerializerMethodField()

    class Meta:
        model = Parameter
        fields = ["name", "type", "description", "required", "value", "is_secret"]
        list_serializer_class = ParamListSerializer

    def get_value(self, param: Parameter):
        if hasattr(param, "value") and hasattr(param, "is_from_org"):
            if param.is_secret and param.is_from_org:
                return "redacted"
            return param.value


class PythonListConfigSerializer(rfs.ListSerializer):
    plugins = rfs.PrimaryKeyRelatedField(read_only=True)

    def to_representation_single_plugin(self, plugin: PythonConfig, user: User):
        cache_name = (
            f"serializer_{plugin.__class__.__name__}_{plugin.name}_{user.username}"
        )
        cache_hit = cache.get(cache_name)
        if not cache_hit:
            plugin_representation = self.child.to_representation(plugin)
            plugin_representation["secrets"] = {}
            plugin_representation["params"] = {}
            total_parameters = 0
            parameter_required_not_configured = []
            for param in plugin.python_module.parameters.annotate_configured(
                plugin, user
            ).annotate_value_for_user(plugin, user):
                total_parameters += 1
                if param.required and not param.configured:
                    parameter_required_not_configured.append(param.name)
                param_representation = ParameterSerializer(param).data
                param_representation.pop("name")
                key = "secrets" if param.is_secret else "params"

                plugin_representation[key][param.name] = param_representation

            if not parameter_required_not_configured:
                logger.debug(f"Plugin {plugin.name} is configured")
                configured = True
                details = "Ready to use!"
            else:
                logger.debug(f"Plugin {plugin.name} is not configured")
                details = (
                    f"{', '.join(parameter_required_not_configured)} "
                    "secret"
                    f"{'' if len(parameter_required_not_configured) == 1 else 's'}"
                    " not set;"
                    f" ({total_parameters - len(parameter_required_not_configured)} "
                    f"of {total_parameters} satisfied)"
                )
                configured = False
            plugin_representation["disabled"] = not plugin.enabled_for_user(user)
            plugin_representation["verification"] = {
                "configured": configured,
                "details": details,
                "missing_secrets": parameter_required_not_configured,
            }
            logger.info(f"Setting cache {cache_name}")
            cache.set(cache_name, plugin_representation, timeout=24 * 7)
        return cache.get(cache_name)

    def to_representation(self, data):
        user = self.context["request"].user
        for plugin in data:
            yield self.to_representation_single_plugin(plugin, user)


class PythonModuleSerializer(rfs.ModelSerializer):
    class Meta:
        model = PythonModule
        fields = ["module", "base_path"]


class ParameterCompleteSerializer(rfs.ModelSerializer):
    python_module = PythonModuleSerializer(read_only=True)

    class Meta:
        model = Parameter
        exclude = ["id"]


class PluginConfigCompleteSerializer(rfs.ModelSerializer):
    parameter = ParameterCompleteSerializer(read_only=True)

    class Meta:
        model = PluginConfig
        exclude = ["id"]


class AbstractConfigSerializer(rfs.ModelSerializer):
    ...


class PythonConfigSerializer(AbstractConfigSerializer):
    parameters = ParameterSerializer(write_only=True, many=True)

    class Meta:
        exclude = [
            "disabled_in_organizations",
            "python_module",
            "routing_key",
            "soft_time_limit",
            "health_check_status",
            "health_check_task",
        ]
        list_serializer_class = PythonListConfigSerializer

    def to_internal_value(self, data):
        raise NotImplementedError()

    def to_representation(self, instance: PythonConfig):
        result = super().to_representation(instance)
        result["disabled"] = result["disabled"] | instance.health_check_status
        result["config"] = {
            "queue": instance.get_routing_key(),
            "soft_time_limit": instance.soft_time_limit,
        }
        return result


class PythonConfigSerializerForMigration(PythonConfigSerializer):
    python_module = PythonModuleSerializer(read_only=True)

    class Meta:
        exclude = ["disabled_in_organizations"]

    def to_representation(self, instance):
        return super(PythonConfigSerializer, self).to_representation(instance)


class AbstractReportSerializerInterface(rfs.ModelSerializer):
    name = rfs.SlugRelatedField(read_only=True, source="config", slug_field="name")
    type = rfs.SerializerMethodField(read_only=True, method_name="get_type")

    class Meta:
        fields = ["name", "process_time", "status", "end_time", "parameters", "type"]
        list_serializer_class = rfs.ListSerializer

    def get_type(self, instance: AbstractReport):
        return instance.__class__.__name__.replace("Report", "").lower()

    def to_internal_value(self, data):
        raise NotImplementedError()


class AbstractBIInterface(ModelSerializer):
    application = rfs.CharField(read_only=True, default="IntelOwl")
    environment = rfs.SerializerMethodField(method_name="get_environment")
    timestamp: Field
    username: Field
    name: Field
    type: Field
    process_time: Field
    status: Field
    end_time: Field

    class Meta:
        fields = [
            "application",
            "environment",
            "timestamp",
            "username",
            "name",
            "type",
            "process_time",
            "status",
            "end_time",
        ]

    @staticmethod
    def get_environment(instance):
        if settings.STAGE_PRODUCTION:
            return "prod"
        elif settings.STAGE_STAGING:
            return "stag"
        else:
            return "test"

    @staticmethod
    def to_elastic_dict(data):
        return {
            "_source": data,
            "_type": "_doc",
            "_index": settings.ELASTICSEARCH_BI_INDEX + "-" + now().strftime("%Y.%m"),
            "_op_type": "index",
        }


class AbstractReportBISerializer(
    AbstractBIInterface, AbstractReportSerializerInterface
):
    timestamp = rfs.DateTimeField(source="start_time")
    username = rfs.CharField(source="job.user.username")

    class Meta:
        fields = AbstractBIInterface.Meta.fields + [
            "parameters",
        ]
        list_serializer_class = (
            AbstractReportSerializerInterface.Meta.list_serializer_class
        )

    def to_representation(self, instance: AbstractReport):
        data = super().to_representation(instance)
        return self.to_elastic_dict(data)


class JobBISerializer(AbstractBIInterface, ModelSerializer):
    timestamp = rfs.DateTimeField(source="received_request_time")
    username = rfs.CharField(source="user.username")
    name = rfs.CharField(source="pk")
    type = rfs.SerializerMethodField(read_only=True, method_name="get_type")
    end_time = rfs.DateTimeField(source="finished_analysis_time")
    playbook = rfs.SerializerMethodField(source="get_playbook")

    class Meta:
        model = Job
        fields = AbstractBIInterface.Meta.fields + ["playbook", "runtime_configuration"]
        list_serializer_class = (
            AbstractReportSerializerInterface.Meta.list_serializer_class
        )

    def to_representation(self, instance: Job):
        data = super().to_representation(instance)
        return self.to_elastic_dict(data)

    def get_type(self, instance: Job):
        return instance.__class__.__name__.lower()

    def get_playbook(self, instance: Job):
        return instance.playbook_to_execute.name if instance.playbook_to_execute else ""


class AbstractReportSerializer(AbstractReportSerializerInterface):
    class Meta:
        fields = AbstractReportSerializerInterface.Meta.fields + [
            "id",
            "report",
            "errors",
            "start_time",
        ]
        list_serializer_class = (
            AbstractReportSerializerInterface.Meta.list_serializer_class
        )


class CrontabScheduleSerializer(rfs.ModelSerializer):
    class Meta:
        model = CrontabSchedule
        fields = [
            "minute",
            "hour",
            "day_of_week",
            "day_of_month",
            "month_of_year",
        ]


class PeriodicTaskSerializer(rfs.ModelSerializer):
    crontab = CrontabScheduleSerializer(read_only=True)

    class Meta:
        model = PeriodicTask
        fields = [
            "crontab",
            "name",
            "task",
            "kwargs",
            "queue",
            "enabled",
        ]
