import copy
import datetime
import ipaddress
import logging
import re
import uuid
from typing import Dict, Generator, List, Union

import django.core
from django.conf import settings
from django.db.models import Q, QuerySet
from django.http import QueryDict
from django.utils.timezone import now
from rest_framework import serializers as rfs
from rest_framework.exceptions import ValidationError
from rest_framework.fields import empty
from rest_framework.serializers import ModelSerializer

from api_app.analyzables_manager.models import Analyzable
from api_app.analyzers_manager.constants import TypeChoices
from api_app.analyzers_manager.models import AnalyzerConfig, MimeTypes
from api_app.choices import TLP, Classification, ScanMode
from api_app.connectors_manager.exceptions import NotRunnableConnector
from api_app.connectors_manager.models import ConnectorConfig
from api_app.defaults import default_runtime
from api_app.helpers import calculate_md5, gen_random_colorhex
from api_app.investigations_manager.models import Investigation
from api_app.models import Comment, Job, Tag
from api_app.playbooks_manager.models import PlaybookConfig
from api_app.serializers import AbstractBIInterface
from api_app.serializers.report import AbstractReportSerializerInterface
from api_app.visualizers_manager.models import VisualizerConfig
from certego_saas.apps.organization.permissions import IsObjectOwnerOrSameOrgPermission
from certego_saas.apps.user.models import User
from intel_owl.celery import get_queue_name

logger = logging.getLogger(__name__)


class JobRelatedField(rfs.PrimaryKeyRelatedField):
    def get_queryset(self):
        if "request" in self.context:
            request = self.context.get("request")
            return super().get_queryset().filter(owner=request.user)
        return super().get_queryset()


class UserSerializer(rfs.ModelSerializer):
    class Meta:
        model = User
        fields = ("username",)


class TagSerializer(rfs.ModelSerializer):
    class Meta:
        model = Tag
        fields = rfs.ALL_FIELDS


class JobRecentScanSerializer(rfs.ModelSerializer):
    playbook = rfs.CharField(source="playbook_to_execute.name", allow_null=True, read_only=True)
    user = rfs.CharField(source="user.username", allow_null=False, read_only=True)
    importance = rfs.IntegerField(allow_null=True, read_only=True)
    observable_name = rfs.CharField(source="analyzable.name", read_only=True, allow_null=True)
    file_name = rfs.CharField(source="analyzable.name", read_only=True, allow_null=True)

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
            "delay",
            "tlp",
            "runtime_configuration",
            "analyzers_requested",
            "connectors_requested",
            "playbook_requested",
            "tags_labels",
            "scan_mode",
            "scan_check_time",
            "investigation",
            "parent_job",
        )

    md5 = rfs.HiddenField(default=None)
    user = rfs.HiddenField(default=rfs.CurrentUserDefault())
    delay = rfs.IntegerField(default=0)
    scan_mode = rfs.ChoiceField(
        choices=ScanMode.choices,
        required=False,
    )
    scan_check_time = rfs.DurationField(required=False, allow_null=True)

    tags_labels = rfs.ListField(child=rfs.CharField(required=True), default=list, required=False)
    runtime_configuration = rfs.JSONField(required=False, write_only=True)
    tlp = rfs.ChoiceField(choices=TLP.values + ["WHITE"], required=False)
    investigation = rfs.PrimaryKeyRelatedField(
        queryset=Investigation.objects.all(), many=False, required=False, default=None
    )
    parent_job = rfs.PrimaryKeyRelatedField(queryset=Job.objects.all(), required=False)
    connectors_requested = rfs.SlugRelatedField(
        slug_field="name",
        queryset=ConnectorConfig.objects.all(),
        many=True,
        default=[],
    )
    analyzers_requested = rfs.SlugRelatedField(
        slug_field="name",
        queryset=AnalyzerConfig.objects.all(),
        many=True,
        default=[],
    )
    playbook_requested = rfs.SlugRelatedField(
        slug_field="name",
        queryset=PlaybookConfig.objects.all(),
        many=False,
        required=False,
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.filter_warnings = []

    def validate_runtime_configuration(self, runtime_config: Dict):  # skipcq: PYL-R0201
        from api_app.validators import validate_runtime_configuration

        if not runtime_config:
            runtime_config = default_runtime()
        try:
            validate_runtime_configuration(runtime_config)
        except django.core.exceptions.ValidationError as e:
            logger.info(e, stack_info=True)
            raise ValidationError({"detail": "Runtime Configuration Validation Failed"})
        return runtime_config

    def validate_tags_labels(self, tags_labels):  # skipcq: PYL-R0201
        for label in tags_labels:
            yield Tag.objects.get_or_create(label=label, defaults={"color": gen_random_colorhex()})[0]

    def validate_tlp(self, tlp: str):  # skipcq: PYL-R0201
        if tlp == "WHITE":
            return TLP.CLEAR.value
        return tlp

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

    def validate_investigation(self, investigation: Investigation = None):
        if investigation and not investigation.user_can_edit(self.context["request"].user):
            raise ValidationError({"detail": "You can't create a job to this investigation"})
        return investigation

    def validate(self, attrs: dict) -> dict:
        if attrs.get("playbook_requested"):
            self.set_default_value_from_playbook(attrs)
        # this TLP validation must be after the Playbook checks to avoid
        # to overwrite the Playbook default TLP
        if "tlp" not in attrs:
            attrs["tlp"] = TLP.CLEAR.value
        if "scan_mode" not in attrs:
            attrs["scan_mode"] = ScanMode.CHECK_PREVIOUS_ANALYSIS.value
        if attrs.get("scan_mode") == ScanMode.CHECK_PREVIOUS_ANALYSIS.value and not attrs.get(
            "scan_check_time"
        ):
            attrs["scan_check_time"] = datetime.timedelta(hours=24)
        elif attrs.get("scan_mode") == ScanMode.FORCE_NEW_ANALYSIS.value:
            attrs["scan_check_time"] = None
        attrs = super().validate(attrs)
        if playbook := attrs.get("playbook_requested", None):
            playbook: PlaybookConfig
            if attrs.get("analyzers_requested", []) or attrs.get("connectors_requested", []):
                raise ValidationError({"detail": "You can't specify a playbook and plugins together"})
            if playbook.disabled:
                raise ValidationError({"detail": "No playbooks can be run after filtering."})
            attrs["playbook_to_execute"] = playbook
            attrs["analyzers_requested"] = list(playbook.analyzers.all())
            attrs["connectors_requested"] = list(playbook.connectors.all())
            attrs["tags_labels"] = list(attrs.get("tags_labels", [])) + list(playbook.tags.all())

        analyzers_to_execute = attrs["analyzers_to_execute"] = self.set_analyzers_to_execute(**attrs)
        connectors_to_execute = attrs["connectors_to_execute"] = self.set_connectors_to_execute(**attrs)
        if not analyzers_to_execute and not connectors_to_execute:
            warnings = "\n".join(self.filter_warnings)
            raise ValidationError(
                {"detail": f"No Analyzers and Connectors can be run after filtering:\n{warnings}"}
            )

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
            visualizers = VisualizerConfig.objects.filter(playbooks__in=[playbook_requested], disabled=False)
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
        return analyzers_executed

    def plugins_to_execute(
        self,
        tlp,
        plugins_requested: Union[List[Union[AnalyzerConfig, ConnectorConfig, VisualizerConfig]], QuerySet],
    ) -> Generator[Union[AnalyzerConfig, ConnectorConfig, VisualizerConfig], None, None]:
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
                    if TLP[tlp] > TLP[plugin_config.maximum_tlp]:  # check if job's tlp allows running
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
            raise ValidationError({"detail": "Scan check time can't be null"})
        status_to_exclude = [Job.STATUSES.KILLED, Job.STATUSES.FAILED]
        if not validated_data.get("playbook_to_execute", None):
            status_to_exclude.append(Job.STATUSES.REPORTED_WITH_FAILS)
        qs = (
            self.Meta.model.objects.visible_for_user(self.context["request"].user)
            .filter(received_request_time__gte=now() - validated_data["scan_check_time"])
            .filter(Q(analyzable__pk=validated_data["analyzable"].pk))
        )
        for analyzer in validated_data.get("analyzers_to_execute", []):
            qs = qs.filter(analyzers_requested__in=[analyzer])
        for connector in validated_data.get("connectors_to_execute", []):
            qs = qs.filter(connectors_requested__in=[connector])
        for visualizer in validated_data.get("visualizers_to_execute", []):
            qs = qs.filter(visualizers_to_execute__in=[visualizer])

        return qs.exclude(status__in=status_to_exclude).latest("received_request_time")

    def create(self, validated_data: Dict) -> Job:
        # POP VALUES!
        # this part is important because a Job doesn't need these fields and it
        # wouldn't know how to handle it. we need these information only at this
        # point of the job creation.
        warnings = validated_data.pop("warnings")
        delay = validated_data.pop("delay")
        send_task = validated_data.pop("send_task", False)
        parent_job = validated_data.pop("parent_job", None)

        # if we have a parent job and a new playbook to excute force new analysis
        # in order to avoid graph related issues
        if validated_data["scan_mode"] == ScanMode.CHECK_PREVIOUS_ANALYSIS.value and not (
            "parent" in validated_data
            and validated_data["parent"]
            and "playbook_to_execute" in validated_data
            and validated_data["playbook_to_execute"]
        ):
            try:
                return self.check_previous_jobs(validated_data)
            except self.Meta.model.DoesNotExist:
                job = super().create(validated_data)
        else:
            job = super().create(validated_data)
        job.warnings = warnings
        job.save()
        logger.info(f"Job {job.pk} created")

        from api_app.pivots_manager.models import PivotMap

        if parent_job:
            PivotMap.objects.create(starting_job=validated_data["parent"], ending_job=job, pivot_config=None)
        if send_task:
            from intel_owl.tasks import job_pipeline

            logger.info(f"Sending task for job {job.pk}")
            job_pipeline.apply_async(
                args=[job.pk],
                queue=get_queue_name(settings.DEFAULT_QUEUE),
                MessageGroupId=str(uuid.uuid4()),
                priority=job.priority,
                # countdown doesn't work as expected and it's just
                # syntactic sugar for the expression below
                eta=now() + datetime.timedelta(seconds=delay),
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
    job_id = rfs.PrimaryKeyRelatedField(queryset=Job.objects.all(), write_only=True, source="job")

    def validate(self, attrs: dict) -> dict:
        attrs = super().validate(attrs)

        user = self.context["request"].user
        job = attrs.get("job")
        try:
            Job.objects.visible_for_user(user).get(pk=job.pk)
        except Job.DoesNotExist:
            raise ValidationError({"detail": f"You have no permission to comment on job {job.pk}"})
        return attrs

    def create(self, validated_data: dict) -> Comment:
        validated_data["user"] = self.context["request"].user
        job = validated_data.pop("job")
        validated_data["analyzable"] = job.analyzable
        return super().create(validated_data)


class JobListSerializer(_AbstractJobViewSerializer):
    """
    Used for ``list()``.
    """

    class Meta:
        model = Job
        fields = (
            "id",
            "user",
            "tags",
            "status",
            "file_name",
            "file_mimetype",
            "is_sample",
            "observable_name",
            "observable_classification",
            "md5",
            "pivots_to_execute",
            "analyzers_to_execute",
            "connectors_to_execute",
            "playbook_to_execute",
            "playbook_requested",
            "visualizers_to_execute",
            "received_request_time",
            "finished_analysis_time",
            "process_time",
            "tlp",
            "investigation",
        )

    pivots_to_execute = rfs.SerializerMethodField(read_only=True)
    analyzers_to_execute = rfs.SlugRelatedField(read_only=True, slug_field="name", many=True)
    connectors_to_execute = rfs.SlugRelatedField(read_only=True, slug_field="name", many=True)
    visualizers_to_execute = rfs.SlugRelatedField(read_only=True, slug_field="name", many=True)
    playbook_to_execute = rfs.SlugRelatedField(read_only=True, slug_field="name")
    file_name = rfs.CharField(source="analyzable.name", read_only=True)
    file_mimetype = rfs.CharField(source="analyzable.mimetype", read_only=True)
    is_sample = rfs.BooleanField(read_only=True)
    observable_name = rfs.CharField(source="analyzable.name", read_only=True)
    observable_classification = rfs.CharField(source="analyzable.classification", read_only=True)
    md5 = rfs.CharField(source="analyzable.md5", read_only=True)

    def get_pivots_to_execute(self, obj: Job):  # skipcq: PYL-R0201
        return obj.pivots_to_execute.all().values_list("name", flat=True)


class JobTreeSerializer(ModelSerializer):
    pivot_config = rfs.CharField(source="pivot_parent.pivot_config.name", allow_null=True, read_only=True)

    evaluation = rfs.CharField(source="data_model.evaluation", allow_null=True, read_only=True)
    reliability = rfs.IntegerField(source="data_model.reliability", allow_null=True, read_only=True)
    tags = rfs.ListField(
        source="data_model.tags",
        allow_null=True,
        child=rfs.CharField(read_only=True),
        read_only=True,
        default=[],
    )
    isp = rfs.CharField(source="data_model.isp", allow_null=True, read_only=True)
    country = rfs.CharField(source="data_model.country_code", allow_null=True, read_only=True)
    is_sample = rfs.BooleanField(read_only=True)

    playbook = rfs.SlugRelatedField(
        source="playbook_to_execute",
        slug_field="name",
        queryset=PlaybookConfig.objects.all(),
        many=False,
        required=False,
    )
    analyzed_object_name = rfs.CharField(source="analyzable.name", read_only=True)
    mimetype = rfs.CharField(source="analyzable.mimetype", allow_null=True, read_only=True)

    class Meta:
        model = Job
        fields = [
            "pk",
            "analyzed_object_name",
            "pivot_config",
            "playbook",
            "status",
            "received_request_time",
            "is_sample",
            "evaluation",
            "reliability",
            "tags",
            "mimetype",
            "isp",
            "country",
        ]

    def to_representation(self, instance):
        instance: Job
        data = super().to_representation(instance)
        for child in instance.get_children():
            # recursive call
            data.setdefault("children", []).append(self.__class__(instance=child).data)
        if data["pivot_config"] is None:
            del data["pivot_config"]
        return data


class JobSerializer(_AbstractJobViewSerializer):
    """
    Used for ``retrieve()``
    """

    class Meta:
        model = Job
        fields = (
            "id",
            "user",
            "tags",
            "comments",
            "status",
            "pivots_to_execute",
            "analyzers_to_execute",
            "analyzers_requested",
            "connectors_to_execute",
            "connectors_requested",
            "visualizers_to_execute",
            "playbook_requested",
            "playbook_to_execute",
            "investigation_id",
            "investigation_name",
            "permissions",
            "data_model",
            "file_name",
            "file_mimetype",
            "is_sample",
            "observable_name",
            "observable_classification",
            "md5",
            "analyzer_reports",
            "connector_reports",
            "pivot_reports",
            "visualizer_reports",
            "analyzable_id",
            "received_request_time",
            "finished_analysis_time",
            "process_time",
            "warnings",
            "errors",
        )

    comments = CommentSerializer(many=True, read_only=True, source="analyzable.comments")
    file_name = rfs.CharField(source="analyzable.name", read_only=True)
    file_mimetype = rfs.CharField(source="analyzable.mimetype", read_only=True)
    observable_name = rfs.CharField(source="analyzable.name", read_only=True)
    observable_classification = rfs.CharField(source="analyzable.classification", read_only=True)
    md5 = rfs.CharField(source="analyzable.md5", read_only=True)

    pivots_to_execute = rfs.SlugRelatedField(many=True, read_only=True, slug_field="name")
    analyzers_to_execute = rfs.SlugRelatedField(many=True, read_only=True, slug_field="name")
    analyzers_requested = rfs.SlugRelatedField(many=True, read_only=True, slug_field="name")
    connectors_to_execute = rfs.SlugRelatedField(many=True, read_only=True, slug_field="name")
    connectors_requested = rfs.SlugRelatedField(many=True, read_only=True, slug_field="name")
    visualizers_to_execute = rfs.SlugRelatedField(many=True, read_only=True, slug_field="name")
    playbook_requested = rfs.SlugRelatedField(read_only=True, slug_field="name")
    playbook_to_execute = rfs.SlugRelatedField(read_only=True, slug_field="name")
    investigation_id = rfs.SerializerMethodField(read_only=True, default=None)
    investigation_name = rfs.SerializerMethodField(read_only=True, default=None)
    analyzable_id = rfs.SerializerMethodField(read_only=True, default=None)
    permissions = rfs.SerializerMethodField()
    data_model = rfs.SerializerMethodField()
    is_sample = rfs.BooleanField(read_only=True)

    def get_pivots_to_execute(self, obj: Job):  # skipcq: PYL-R0201
        # this cast is required or serializer doesn't work with websocket
        return list(obj.pivots_to_execute.all().values_list("name", flat=True))

    def get_investigation_id(self, instance: Job):  # skipcq: PYL-R0201
        if root_investigation := instance.get_root().investigation:
            return root_investigation.pk
        return instance.investigation

    def get_investigation_name(self, instance: Job):  # skipcq: PYL-R0201
        if root_investigation := instance.get_root().investigation:
            return root_investigation.name
        return instance.investigation

    def get_analyzable_id(self, instance: Job) -> int:
        return instance.analyzable.pk

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

    def get_data_model(self, instance: Job):
        if instance.data_model:
            return instance.data_model.serialize()
        return {}


class RestJobSerializer(JobSerializer):
    def get_permissions(self, obj: Job) -> Dict[str, bool]:
        request = self.context.get("request", None)
        view = self.context.get("view", None)
        has_perm = False
        if request and view:
            has_perm = IsObjectOwnerOrSameOrgPermission().has_object_permission(request, view, obj)
        return {
            "kill": has_perm,
            "delete": has_perm,
            "plugin_actions": has_perm,
        }


class WsJobSerializer(JobSerializer):
    def get_permissions(self, obj: Job) -> Dict[str, bool]:
        has_perm = self.context.get("permissions", False)
        return {
            "kill": has_perm,
            "delete": has_perm,
            "plugin_actions": has_perm,
        }


class MultipleJobSerializer(rfs.ListSerializer):
    def update(self, instance, validated_data):
        raise NotImplementedError("This serializer does not support update().")

    def save(self, parent: Job = None, **kwargs):
        jobs = super().save(**kwargs, parent=parent)
        if parent:
            # the parent has already an investigation
            # so we don't need to do anything because everything is already connected
            root = parent.get_root()
            if root.investigation:
                root.investigation.status = root.investigation.STATUSES.RUNNING.value
                root.investigation.save()
                return jobs
            # if we have a parent, it means we are pivoting from one job to another
            else:
                if parent.playbook_to_execute:
                    investigation_name = f"{parent.playbook_to_execute.name}: {parent.analyzable.name}"
                else:
                    investigation_name = f"Pivot investigation: {parent.analyzable.name}"

                investigation = Investigation.objects.create(
                    name=investigation_name,
                    owner=self.context["request"].user,
                )
                investigation.jobs.add(parent)
                investigation.start_time = parent.received_request_time
        else:
            # if we do not have a parent but we have an investigation
            # set investigation into running status
            if len(jobs) >= 1 and jobs[0].investigation:
                investigation = jobs[0].investigation
                investigation.status = investigation.STATUSES.RUNNING.value
                investigation.save()
                return jobs
            # if we do not have a parent or an investigation, and we have multiple jobs,
            # we are in the multiple input case
            elif len(jobs) > 1:
                investigation = Investigation.objects.create(
                    name=f"Custom investigation: {len(jobs)} jobs",
                    owner=self.context["request"].user,
                )
                for job in jobs:
                    job: Job
                    job.investigation = investigation
                    job.save()
                investigation.start_time = now()
            else:
                return jobs
        investigation: Investigation
        investigation.status = investigation.STATUSES.RUNNING.value
        investigation.for_organization = True
        investigation.save()
        return jobs

    def validate(self, attrs: dict) -> dict:
        attrs = super().validate(attrs)
        # filter requests with more elements than this threshold
        max_element_per_request_number = 200
        if len(attrs) > max_element_per_request_number:
            raise ValidationError(
                {
                    "detail": "Exceed the threshold of "
                    f"{max_element_per_request_number}  elements for a single analysis"
                }
            )
        return attrs


class MultipleFileJobSerializer(MultipleJobSerializer):
    """
    ``Job`` model's serializer for Multiple File Analysis.
    Used for ``create()``.
    """

    def update(self, instance, validated_data):
        raise NotImplementedError("This serializer does not support update().")

    files = rfs.ListField(child=rfs.FileField(required=True), required=True)

    file_names = rfs.ListField(child=rfs.CharField(required=True), required=True)

    file_mimetypes = rfs.ListField(child=rfs.CharField(required=True, allow_blank=True), required=False)

    def to_internal_value(self, data: QueryDict):
        ret = []
        errors = []
        if not isinstance(data, QueryDict):
            data_to_check = QueryDict(mutable=True)
            data_to_check.update(data)
        else:
            data_to_check = data
        if data_to_check.getlist("file_names", []) and len(data_to_check.getlist("file_names")) != len(
            data_to_check.getlist("files")
        ):
            raise ValidationError({"detail": "file_names and files must have the same length."})

        for index, file in enumerate(data_to_check.getlist("files")):
            # `deepcopy` here ensures that this code doesn't
            # break even if new fields are added in future
            item = data_to_check.copy()

            item["file"] = file
            if data_to_check.getlist("file_names", []):
                item["file_name"] = data_to_check.getlist("file_names")[index]
            if data_to_check.get("file_mimetypes", []):
                item["file_mimetype"] = data_to_check["file_mimetypes"][index]
            if delay := data_to_check.get("delay", datetime.timedelta()):
                item["delay"] = int(delay * index)
            try:
                validated = self.child.run_validation(item)
            except ValidationError as exc:
                errors.append(exc.detail)
            else:
                ret.append(validated)

        if any(errors):
            raise ValidationError({"detail": errors})

        return ret


class FileJobSerializer(_AbstractJobCreateSerializer):
    """
    ``Job`` model's serializer for File Analysis.
    Used for ``create()``.
    """

    file = rfs.FileField(required=True)
    file_name = rfs.CharField(required=False)
    file_mimetype = rfs.CharField(required=False)

    class Meta:
        model = Job
        fields = _AbstractJobCreateSerializer.Meta.fields + (
            "file",
            "file_name",
            "file_mimetype",
        )
        list_serializer_class = MultipleFileJobSerializer

    def validate(self, attrs: dict) -> dict:
        logger.debug(f"before attrs: {attrs}")
        # calculate ``file_mimetype``
        if "file_name" not in attrs:
            attrs["file_name"] = attrs["file"].name
        # calculate ``md5``
        file_obj = attrs["file"].file
        file_obj.seek(0)
        file_buffer = file_obj.read()
        attrs["file_mimetype"] = MimeTypes.calculate(file_buffer, attrs["file_name"])
        attrs["md5"] = calculate_md5(file_buffer)
        attrs = super().validate(attrs)
        logger.debug(f"after attrs: {attrs}")
        return attrs

    def create(self, validated_data):
        md5 = validated_data.pop("md5")
        sample, created = Analyzable.objects.get_or_create(
            md5=md5,
            defaults={
                "name": validated_data.pop("file_name"),
                "file": validated_data.pop("file"),
                "mimetype": validated_data.pop("file_mimetype"),
                "md5": md5,
                "classification": Classification.FILE.value,
            },
        )
        if created:
            sample.full_clean()
            sample.save()
        validated_data["analyzable"] = sample
        return super().create(validated_data)

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
        if file_mimetype in [MimeTypes.ZIP1.value, MimeTypes.ZIP2.value]:
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

        for analyzer in partially_filtered_analyzers_qs.exclude(Q(type=TypeChoices.FILE) & supported_query):
            analyzers_to_execute.remove(analyzer)
            message = f"{analyzer.name} won't be run because does not support the file mimetype."
            logger.info(message)
            self.filter_warnings.append(message)
        return super().set_analyzers_to_execute(analyzers_to_execute, tlp)


class MultipleObservableJobSerializer(MultipleJobSerializer):
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
        for index, (_, name) in enumerate(observables):  # observable = (classification, name)
            # `deepcopy` here ensures that this code doesn't
            # break even if new fields are added in future
            item = copy.deepcopy(data)
            item["observable_name"] = name

            if delay := data.get("delay", datetime.timedelta()):
                item["delay"] = int(delay * index)

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


class ObservableAnalysisSerializer(_AbstractJobCreateSerializer):
    """
    ``Job`` model's serializer for Observable Analysis.
    Used for ``create()``.
    """

    observable_name = rfs.CharField(required=True)
    observable_classification = rfs.CharField(required=False)

    class Meta:
        model = Job
        fields = _AbstractJobCreateSerializer.Meta.fields + (
            "observable_name",
            "observable_classification",
        )
        list_serializer_class = MultipleObservableJobSerializer

    def create(self, validated_data):
        observable_classification = validated_data.pop("observable_classification")
        md5 = validated_data.pop("md5")
        obs, created = Analyzable.objects.get_or_create(
            defaults={
                "name": validated_data.pop("observable_name"),
                "md5": md5,
                "classification": observable_classification,
            },
            md5=md5,
        )
        if created:
            obs.full_clean()
            obs.save()

        validated_data["analyzable"] = obs

        return super().create(validated_data)

    def validate(self, attrs: dict) -> dict:
        logger.debug(f"before attrs: {attrs}")
        attrs["observable_name"] = self.defanged_values_removal(attrs["observable_name"])
        # calculate ``observable_classification``
        if not attrs.get("observable_classification", None):
            attrs["observable_classification"] = Classification.calculate_observable(attrs["observable_name"])
        if attrs["observable_classification"] in [
            Classification.HASH,
            Classification.DOMAIN,
        ]:
            # force lowercase in ``observable_name``.
            # Ref: https://github.com/intelowlproject/IntelOwl/issues/658
            attrs["observable_name"] = attrs["observable_name"].lower()

        if attrs["observable_classification"] == Classification.IP.value:
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
        logger.debug(f"{analyzers_requested=} {type(analyzers_requested)=}")
        analyzers_to_execute = analyzers_requested.copy()

        partially_filtered_analyzers_qs = AnalyzerConfig.objects.filter(
            pk__in=[config.pk for config in analyzers_to_execute]
        )
        for analyzer in partially_filtered_analyzers_qs.exclude(
            type=TypeChoices.OBSERVABLE,
            observable_supported__contains=[observable_classification],
        ):
            analyzers_to_execute.remove(analyzer)
            message = f"{analyzer.name} won't be run because it does not support the requested observable."
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
    analyzers_running = rfs.SlugRelatedField(
        read_only=True,
        source="analyzers_to_execute",
        many=True,
        slug_field="name",
    )
    connectors_running = rfs.SlugRelatedField(
        read_only=True,
        source="connectors_to_execute",
        many=True,
        slug_field="name",
    )
    visualizers_running = rfs.SlugRelatedField(
        read_only=True,
        source="visualizers_to_execute",
        many=True,
        slug_field="name",
    )
    playbook_running = rfs.SlugRelatedField(
        read_only=True,
        source="playbook_to_execute",
        slug_field="name",
    )
    investigation = rfs.SerializerMethodField(read_only=True, default=None)

    class Meta:
        model = Job
        fields = [
            "job_id",
            "analyzers_running",
            "connectors_running",
            "visualizers_running",
            "playbook_running",
            "investigation",
        ]
        extra_kwargs = {"warnings": {"read_only": True, "required": False}}
        list_serializer_class = JobEnvelopeSerializer

    def get_investigation(self, instance: Job):  # skipcq: PYL-R0201
        if root_investigation := instance.get_root().investigation:
            return root_investigation.pk
        return instance.investigation

    def to_representation(self, instance: Job):
        result = super().to_representation(instance)
        result["status"] = self.STATUS_ACCEPTED
        result["already_exists"] = bool(instance.status in instance.STATUSES.final_statuses())
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
    analyzers = rfs.SlugRelatedField(
        queryset=AnalyzerConfig.objects.all(),
        many=True,
        required=False,
        slug_field="name",
    )
    playbooks = rfs.SlugRelatedField(
        queryset=PlaybookConfig.objects.all(),
        required=False,
        many=True,
        slug_field="name",
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
            raise rfs.ValidationError("Either only send the 'playbooks' parameter or the 'analyzers' one.")
        return attrs

    def create(self, validated_data):
        statuses_to_check = [Job.STATUSES.RUNNING]

        if not validated_data["running_only"]:
            statuses_to_check.append(Job.STATUSES.REPORTED_WITHOUT_FAILS)
            # since with playbook
            # it is expected behavior
            # for analyzers to often fail
            if validated_data.get("playbooks", []):
                statuses_to_check.append(Job.STATUSES.REPORTED_WITH_FAILS)
        # this means that the user is trying to
        # check availability of the case where all
        # analyzers were run but no playbooks were
        # triggered.
        query = Q(analyzable__md5=validated_data["md5"]) & Q(status__in=statuses_to_check)
        if validated_data.get("playbooks", []):
            query &= Q(playbook_requested__name__in=validated_data["playbooks"])
        else:
            analyzers = validated_data.get("analyzers", [])
            for analyzer in analyzers:
                query &= Q(analyzers_requested__name__in=[analyzer])
        # we want a job that has every analyzer requested
        if validated_data.get("minutes_ago", None):
            minutes_ago_time = now() - datetime.timedelta(minutes=validated_data["minutes_ago"])
            query &= Q(received_request_time__gte=minutes_ago_time)

        last_job_for_md5 = (
            Job.objects.visible_for_user(self.context["request"].user)
            .filter(query)
            .only("pk")
            .latest("received_request_time")
        )
        return last_job_for_md5


class JobBISerializer(AbstractBIInterface, ModelSerializer):
    timestamp = rfs.DateTimeField(source="received_request_time")
    username = rfs.CharField(source="user.username")
    end_time = rfs.DateTimeField(source="finished_analysis_time")
    playbook = rfs.SerializerMethodField(source="get_playbook")
    job_id = rfs.CharField(source="pk")
    is_sample = rfs.BooleanField(read_only=True)

    class Meta:
        model = Job
        fields = AbstractBIInterface.Meta.fields + [
            "playbook",
            "runtime_configuration",
            "is_sample",
        ]
        list_serializer_class = AbstractReportSerializerInterface.Meta.list_serializer_class

    def to_representation(self, instance: Job):
        data = super().to_representation(instance)
        return self.to_elastic_dict(data, self.get_index())

    @staticmethod
    def get_playbook(instance: Job):
        return instance.playbook_to_execute.name if instance.playbook_to_execute else ""


class JobAnalyzableHistorySerializer(rfs.ModelSerializer):
    id = rfs.CharField(source="pk")
    user = rfs.CharField(source="user.username", allow_null=False, read_only=True)
    data_model = rfs.SerializerMethodField()
    date = rfs.DateTimeField(source="finished_analysis_time", read_only=True, allow_null=False)
    playbook = rfs.CharField(source="playbook_to_execute.name", allow_null=True, read_only=True)

    class Meta:
        model = Job
        fields = ["playbook", "user", "date", "data_model", "id"]

    def get_data_model(self, instance: Job):
        logger.debug(f"{instance=}")
        logger.debug(f"{instance.analyzable=}")

        if instance.data_model:
            return instance.data_model.serialize()
        return {}
