# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import copy
import datetime
import json
import logging
import uuid
from typing import Dict, List, Union, Any

import django.core.exceptions
from django.db.models import Q
from django.http import QueryDict
from django.utils.timezone import now
from durin.serializers import UserSerializer
from rest_framework import serializers as rfs
from rest_framework.exceptions import PermissionDenied, ValidationError

from certego_saas.apps.organization.membership import Membership
from certego_saas.apps.organization.organization import Organization
from certego_saas.apps.organization.permissions import IsObjectOwnerOrSameOrgPermission
from intel_owl.celery import DEFAULT_QUEUE

from .analyzers_manager.constants import ObservableTypes, TypeChoices
from .analyzers_manager.models import AnalyzerConfig, MimeTypes
from .analyzers_manager.serializers import AnalyzerReportSerializer
from .choices import TLP
from .connectors_manager.exceptions import NotRunnableConnector
from .connectors_manager.models import ConnectorConfig
from .connectors_manager.serializers import ConnectorReportSerializer
from .core.models import Parameter
from .helpers import calculate_md5, gen_random_colorhex
from .models import Comment, Job, PluginConfig, Tag, default_runtime
from .playbooks_manager.models import PlaybookConfig
from .visualizers_manager.models import VisualizerConfig
from .visualizers_manager.serializers import VisualizerReportSerializer

logger = logging.getLogger(__name__)

__all__ = [
    "TagSerializer",
    "JobAvailabilitySerializer",
    "JobListSerializer",
    "JobSerializer",
    "FileAnalysisSerializer",
    "ObservableAnalysisSerializer",
    "JobResponseSerializer",
    "MultipleFileAnalysisSerializer",
    "MultipleObservableAnalysisSerializer",
    "PluginConfigSerializer",
    "CommentSerializer",
]


# User = get_user_model()


class TagSerializer(rfs.ModelSerializer):
    class Meta:
        model = Tag
        fields = rfs.ALL_FIELDS


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

    tags_labels = rfs.ListField(default=list)
    runtime_configuration = rfs.JSONField(
        required=False, default=default_runtime, write_only=True
    )
    md5 = rfs.HiddenField(default=None)
    tlp = rfs.ChoiceField(choices=TLP.values + ["WHITE"], default=TLP.CLEAR)

    def validate_runtime_configuration(self, runtime_config: Dict):
        from api_app.validators import validate_runtime_configuration

        if not runtime_config:
            runtime_config = default_runtime()
        try:
            validate_runtime_configuration(runtime_config)
        except django.core.exceptions.ValidationError as e:
            raise ValidationError(str(e))
        return runtime_config

    def validate_tlp(self, tlp: str):
        if tlp == "WHITE":
            return TLP.CLEAR.value
        return tlp

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.filter_warnings = []
        self.log_runnable = True
        self.mtm_fields = {
            "analyzers_requested": None,
            "connectors_requested": None,
            "analyzers_to_execute": None,
            "connectors_to_execute": None,
            "visualizers_to_execute": None,
        }

    def validate(self, attrs: dict) -> dict:
        attrs = super().validate(attrs)
        if playbook := attrs.get("playbook_requested", None):
            if attrs.get("analyzers_requested", []) or attrs.get(
                "connectors_requested", []
            ):
                raise ValidationError(
                    "You can't specify a playbook and plugins together"
                )
            if playbook.disabled:
                raise ValidationError(
                    {"detail": "No playbooks can be run after filtering."}
                )
            attrs["playbook_to_execute"] = playbook
            attrs["analyzers_requested"] = list(playbook.analyzers.all())
            attrs["connectors_requested"] = list(playbook.connectors.all())

        attrs["analyzers_requested"] = self.filter_analyzers_requested(
            attrs["analyzers_requested"]
        )
        attrs["connectors_requested"] = self.filter_connectors_requested(
            attrs["connectors_requested"]
        )
        attrs["analyzers_to_execute"] = self.set_analyzers_to_execute(
            attrs["analyzers_requested"], attrs
        )
        attrs["connectors_to_execute"] = self.set_connectors_to_execute(
            attrs["connectors_requested"], attrs
        )
        attrs["visualizers_to_execute"] = self.set_visualizers_to_execute(
            attrs["analyzers_to_execute"], attrs["connectors_to_execute"]
        )
        attrs["warnings"] = self.filter_warnings

        return attrs

    def set_visualizers_to_execute(
        self,
        analyzers_to_execute: List[AnalyzerConfig],
        connectors_to_execute: List[ConnectorConfig],
    ) -> List[VisualizerConfig]:
        visualizers_to_execute = []

        for visualizer in VisualizerConfig.objects.all():
            visualizer: VisualizerConfig
            if (
                visualizer.is_runnable(self.context["request"].user)
                # subsets
                and set(visualizer.analyzers.all().values_list("pk", flat=True))
                <= {analyzer.pk for analyzer in analyzers_to_execute}
                and set(visualizer.connectors.all().values_list("pk", flat=True))
                <= {connector.pk for connector in connectors_to_execute}
            ):
                logger.info(f"Going to use {visualizer.name}")
                visualizers_to_execute.append(visualizer)
        return visualizers_to_execute

    def set_connectors_to_execute(
        self, connectors_requested: List[ConnectorConfig], serialized_data
    ) -> List[ConnectorConfig]:
        tlp = serialized_data["tlp"]
        connectors_executed = self.plugins_to_execute(
            tlp, connectors_requested, not self.all_connectors
        )
        return connectors_executed

    def set_analyzers_to_execute(
        self, analyzers_requested: List[AnalyzerConfig], serialized_data
    ) -> List[AnalyzerConfig]:
        tlp = serialized_data["tlp"]
        analyzers_executed = self.plugins_to_execute(
            tlp, analyzers_requested, not self.all_analyzers
        )
        if not analyzers_executed:
            raise ValidationError(
                {"detail": "No Analyzers can be run after filtering."}
            )
        return analyzers_executed

    def plugins_to_execute(
        self,
        tlp,
        plugins_requested: List[Union[AnalyzerConfig, ConnectorConfig]],
        add_warning: bool = False,
    ) -> List[Union[AnalyzerConfig, ConnectorConfig]]:
        plugins_to_execute = plugins_requested.copy()
        for plugin_config in plugins_requested:
            try:
                if not plugin_config.is_runnable(self.context["request"].user):
                    raise NotRunnableConnector(
                        f"{plugin_config.name} won't run: is disabled or not configured"
                    )

                if TLP.get_priority(tlp) > TLP.get_priority(
                    plugin_config.maximum_tlp
                ):  # check if job's tlp allows running
                    # e.g. if connector_tlp is GREEN(1),
                    # run for job_tlp CLEAR(0) & GREEN(1) only
                    raise NotRunnableConnector(
                        f"{plugin_config.name} won't run: "
                        f"job.tlp ('{tlp}') >"
                        f" maximum_tlp ('{plugin_config.maximum_tlp}')"
                    )
            except NotRunnableConnector as e:
                plugins_to_execute.remove(plugin_config)
                if add_warning:
                    logger.info(e)
                    self.filter_warnings.append(str(e))
                else:
                    logger.debug(e)

        return plugins_to_execute

    def filter_analyzers_requested(self, analyzers):
        self.all_analyzers = False
        if not analyzers:
            analyzers = list(AnalyzerConfig.objects.all())
            self.all_analyzers = True
        return analyzers

    def filter_connectors_requested(self, connectors):
        self.all_connectors = False
        if not connectors:
            connectors = list(ConnectorConfig.objects.all())
            self.all_connectors = True
        return connectors

    def create(self, validated_data: dict) -> Job:
        # create ``Tag`` objects from tags_labels
        tags_labels = validated_data.pop("tags_labels", None)
        validated_data.pop("warnings")
        send_task = validated_data.pop("send_task", False)
        tags = [
            Tag.objects.get_or_create(
                label=label, defaults={"color": gen_random_colorhex()}
            )[0]
            for label in tags_labels
        ]
        for key in self.mtm_fields:
            self.mtm_fields[key] = validated_data.pop(key)

        job = Job(user=self.context["request"].user, **validated_data)
        try:
            job.full_clean()
        except django.core.exceptions.ValidationError as e:
            raise ValidationError(str(e))
        job.save()
        if tags:
            job.tags.set(tags)

        for key, value in self.mtm_fields.items():
            mtm = getattr(job, key)
            mtm.set(value)
        if send_task:
            from intel_owl.tasks import job_pipeline

            logger.info("Sending task")
            job_pipeline.apply_async(
                args=[job.pk],
                routing_key=DEFAULT_QUEUE,
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
            Job.visible_for_user(user).get(pk=job.pk)
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
        exclude = ("file", "errors")


class JobSerializer(_AbstractJobViewSerializer):
    """
    Used for ``retrieve()``
    """

    class Meta:
        model = Job
        exclude = ("file",)

    analyzer_reports = AnalyzerReportSerializer(
        many=True, read_only=True, source="analyzerreports"
    )
    connector_reports = ConnectorReportSerializer(
        many=True, read_only=True, source="connectorreports"
    )
    visualizer_reports = VisualizerReportSerializer(
        many=True, read_only=True, source="visualizerreports"
    )
    comments = CommentSerializer(many=True, read_only=True)

    permissions = rfs.SerializerMethodField()

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

        if data.getlist("file_names", False) and len(data.getlist("file_names")) != len(
            data.getlist("files")
        ):
            raise ValidationError("file_names and files must have the same length.")

        try:
            base_data: QueryDict = data.copy()
        except TypeError:  # https://code.djangoproject.com/ticket/29510
            base_data: QueryDict = QueryDict(mutable=True)
            for key, value_list in data.lists():
                if key not in ["files", "file_names", "file_mimetypes"]:
                    base_data.setlist(key, copy.deepcopy(value_list))

        for index, file in enumerate(data.getlist("files")):
            # `deepcopy` here ensures that this code doesn't
            # break even if new fields are added in future
            item = base_data.copy()

            item["file"] = file
            if data.getlist("file_names", False):
                item["file_name"] = data.getlist("file_names")[index]
            if data.get("file_mimetypes", False):
                item["file_mimetype"] = data["file_mimetypes"][index]
            try:
                validated = self.child.run_validation(item)
            except ValidationError as exc:
                errors.append(exc.detail)
            else:
                ret.append(validated)

        if any(errors):
            raise ValidationError(errors)

        return ret


class MultiplePlaybooksMultipleFileAnalysisSerializer(MultipleFileAnalysisSerializer):
    playbooks_requested = rfs.PrimaryKeyRelatedField(
        queryset=PlaybookConfig.objects.all(), many=True
    )

    def to_internal_value(self, data):
        ret = []
        for playbook in data.pop("playbooks_requested", [None]):
            item = copy.deepcopy(data)
            item["playbook_requested"] = playbook
            results = super().to_internal_value(item)
            ret.extend(results)
        return ret


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
        fields = (
            "id",
            "user",
            "is_sample",
            "md5",
            "tlp",
            "file",
            "file_name",
            "file_mimetype",
            "runtime_configuration",
            "analyzers_requested",
            "connectors_requested",
            "playbook_requested",
            "tags_labels",
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
        try:
            attrs["file_mimetype"] = MimeTypes.calculate(
                attrs["file"], attrs["file_name"]
            )
        except ValueError as e:
            raise ValidationError(e)
        # calculate ``md5``
        file_obj = attrs["file"].file
        file_obj.seek(0)
        file_buffer = file_obj.read()
        attrs["md5"] = calculate_md5(file_buffer)
        attrs = super().validate(attrs)
        logger.debug(f"after attrs: {attrs}")
        return attrs

    def set_analyzers_to_execute(
        self, analyzers_requested: List[AnalyzerConfig], serialized_data
    ) -> List[AnalyzerConfig]:
        analyzers_to_execute = analyzers_requested.copy()

        # get values from serializer
        partially_filtered_analyzers_qs = AnalyzerConfig.objects.filter(
            pk__in=[config.pk for config in analyzers_to_execute]
        )
        file_mimetype = serialized_data["file_mimetype"]

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
            if self.all_analyzers:
                logger.debug(message)
            else:
                logger.info(message)
                self.filter_warnings.append(message)
        return super().set_analyzers_to_execute(analyzers_to_execute, serialized_data)


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
        for classification, name in data.pop("observables", []):

            # `deepcopy` here ensures that this code doesn't
            # break even if new fields are added in future
            item = copy.deepcopy(data)

            item["observable_name"] = name
            if classification:
                item["observable_classification"] = classification
            try:
                validated = self.child.run_validation(item)
            except ValidationError as exc:
                errors.append(exc.detail)
            else:
                ret.append(validated)
        if any(errors):
            raise ValidationError(errors)
        return ret


class MultiplePlaybooksMultipleObservableAnalysisSerializer(
    MultipleObservableAnalysisSerializer
):
    playbooks_requested = rfs.PrimaryKeyRelatedField(
        queryset=PlaybookConfig.objects.all(), many=True
    )

    def to_internal_value(self, data):
        ret = []
        for playbook in data.pop("playbooks_requested", [None]):
            item = copy.deepcopy(data)
            item["playbook_requested"] = playbook
            results = super().to_internal_value(item)
            ret.extend(results)
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
        fields = (
            "id",
            "user",
            "is_sample",
            "md5",
            "tlp",
            "observable_name",
            "observable_classification",
            "runtime_configuration",
            "analyzers_requested",
            "connectors_requested",
            "playbook_requested",
            "tags_labels",
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
        # calculate ``observable_classification``
        if not attrs.get("observable_classification", None):
            attrs["observable_classification"] = ObservableTypes.calculate(
                attrs["observable_name"]
            )
        attrs["observable_name"] = self.defanged_values_removal(
            attrs["observable_name"]
        )
        if attrs["observable_classification"] in [
            ObservableTypes.HASH,
            ObservableTypes.DOMAIN,
        ]:
            # force lowercase in ``observable_name``.
            # Ref: https://github.com/intelowlproject/IntelOwl/issues/658
            attrs["observable_name"] = attrs["observable_name"].lower()
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
        self, analyzers_requested: List[AnalyzerConfig], serialized_data
    ) -> List[AnalyzerConfig]:
        analyzers_to_execute = analyzers_requested.copy()

        partially_filtered_analyzers_qs = AnalyzerConfig.objects.filter(
            pk__in=[config.pk for config in analyzers_to_execute]
        )
        for analyzer in partially_filtered_analyzers_qs.exclude(
            type=TypeChoices.OBSERVABLE,
            observable_supported__contains=[
                serialized_data["observable_classification"]
            ],
        ):
            analyzers_to_execute.remove(analyzer)
            message = (
                f"{analyzer.name} won't be run because"
                " it does not support the requested observable."
            )
            if self.all_analyzers:
                logger.debug(message)
            else:
                logger.info(message)
                self.filter_warnings.append(message)

        return super().set_analyzers_to_execute(analyzers_to_execute, serialized_data)


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

    def to_representation(self, instance):
        result = super().to_representation(instance)
        result["status"] = self.STATUS_ACCEPTED
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
            Job.visible_for_user(self.context["request"].user)
            .filter(query)
            .only("pk")
            .latest("received_request_time")
        )
        return last_job_for_md5


class PluginConfigSerializer(rfs.ModelSerializer):
    class Meta:
        model = PluginConfig
        fields = ("attribute", "config_type", "type", "plugin_name", "value", "owner", "organization", "id")

    class CustomValueField(rfs.JSONField):
        def to_internal_value(self, data):
            if not data:
                raise ValidationError("empty insertion")
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
                    raise ValidationError("Value is not JSON-compliant.")

        def get_attribute(self, instance: PluginConfig):
            if (
                instance.is_secret()
                and instance.for_organization
                and self.context["request"].user.pk != instance.owner.pk
            ):
                return "redacted"
            return super().get_attribute(instance)

        def to_representation(self, value):
            result = super().to_representation(value)
            return json.dumps(result)

    type = rfs.ChoiceField(choices=["1", "2", "3"]) # retrocompatibility
    config_type = rfs.ChoiceField(choices=["1", "3"]) # retrocompatibility
    attribute = rfs.CharField()
    plugin_name = rfs.CharField()
    owner = rfs.HiddenField(default=rfs.CurrentUserDefault())

    organization = rfs.PrimaryKeyRelatedField(queryset=Organization.objects.all(), required=False, allow_null=True)
    value = CustomValueField()

    def validate_value_type(self, value:Any, parameter: Parameter):
        if type(value).__name__ != parameter.type:
            raise ValidationError(f"Value has type {type(value).__name__} instead of {parameter.type}")

    def validate(self, attrs):
        if self.partial:
            # we are in an update
            return attrs
        if "organization" in attrs and attrs["organization"] and (attrs.pop("organization").owner != attrs["owner"]):
            attrs["for_organization"] = True
            raise ValidationError("You are not owner of the organization")

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
        else:
            raise RuntimeError("Not configured")
        parameter = class_.objects.get(name=_plugin_name).parameters.get(name=_attribute, is_secret=True if _config_type =="2" else False)
        self.validate_value_type(_value, parameter)
        attrs["parameter"] = parameter
        return attrs

    def update(self, instance, validated_data):
        self.validate_value_type(validated_data["value"], instance.parameter)
        return super().update(instance, validated_data)

