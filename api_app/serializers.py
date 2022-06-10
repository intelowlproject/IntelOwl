# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
import copy
import json
import logging
from typing import Dict, List

from drf_spectacular.utils import extend_schema_serializer
from durin.serializers import UserSerializer
from rest_framework import serializers as rfs
from rest_framework.exceptions import ValidationError

from certego_saas.apps.organization.permissions import IsObjectOwnerOrSameOrgPermission

from .analyzers_manager.constants import ObservableTypes
from .analyzers_manager.dataclasses import AnalyzerConfig
from .analyzers_manager.serializers import AnalyzerReportSerializer
from .connectors_manager.dataclasses import ConnectorConfig
from .connectors_manager.serializers import ConnectorReportSerializer
from .exceptions import NotRunnableAnalyzer, NotRunnableConnector
from .helpers import (
    calculate_md5,
    calculate_mimetype,
    calculate_observable_classification,
    gen_random_colorhex,
)
from .models import TLP, Job, Tag

logger = logging.getLogger(__name__)

__all__ = [
    "TagSerializer",
    "JobAvailabilitySerializer",
    "JobListSerializer",
    "JobSerializer",
    "FileAnalysisSerializer",
    "ObservableAnalysisSerializer",
    "AnalysisResponseSerializer",
    "multi_result_enveloper",
]


class TagSerializer(rfs.ModelSerializer):
    class Meta:
        model = Tag
        fields = rfs.ALL_FIELDS


class JobAvailabilitySerializer(rfs.ModelSerializer):
    """
    Serializer for ask_analysis_availability
    """

    class Meta:
        model = Job
        fields = rfs.ALL_FIELDS

    md5 = rfs.CharField(max_length=128, required=True)
    analyzers = rfs.ListField(default=list)
    running_only = rfs.BooleanField(default=False, required=False)
    minutes_ago = rfs.IntegerField(default=None, required=False)


class _AbstractJobViewSerializer(rfs.ModelSerializer):
    """
    Base Serializer for ``Job`` model's ``retrieve()`` and ``list()``.
    """

    user = UserSerializer()
    tags = TagSerializer(many=True, read_only=True)
    process_time = rfs.FloatField()


class _AbstractJobCreateSerializer(rfs.ModelSerializer):
    """
    Base Serializer for ``Job`` model's ``create()``.
    """

    tags_labels = rfs.ListField(default=list)
    runtime_configuration = rfs.JSONField(required=False, default={}, write_only=True)
    analyzers_requested = rfs.ListField(default=list)
    connectors_requested = rfs.ListField(default=list)
    md5 = rfs.HiddenField(default=None)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.filter_warnings = []

    def validate(self, attrs: dict) -> dict:
        # check and validate runtime_configuration
        runtime_conf = attrs.get("runtime_configuration", {})
        if runtime_conf and isinstance(runtime_conf, list):
            runtime_conf = json.loads(runtime_conf[0])
        attrs["runtime_configuration"] = runtime_conf
        return attrs

    def filter_analyzers(self, serialized_data: Dict) -> List[str]:
        # init empty list
        cleaned_analyzer_list = []
        selected_analyzers = []

        # get values from serializer
        analyzers_requested = serialized_data.get("analyzers_requested", [])
        tlp = serialized_data.get("tlp", TLP.WHITE).upper()

        # read config
        analyzer_dataclasses = AnalyzerConfig.all()
        all_analyzer_names = list(analyzer_dataclasses.keys())

        # run all analyzers ?
        run_all = len(analyzers_requested) == 0
        if run_all:
            # select all
            selected_analyzers.extend(all_analyzer_names)
        else:
            # select the ones requested
            selected_analyzers.extend(analyzers_requested)

        for a_name in selected_analyzers:
            try:
                config = analyzer_dataclasses.get(a_name, None)

                if not config:
                    if not run_all:
                        raise NotRunnableAnalyzer(
                            f"{a_name} won't run: not available in configuration"
                        )
                    # don't add warning if run_all
                    continue

                if not config.is_ready_to_use:
                    raise NotRunnableAnalyzer(
                        f"{a_name} won't run: is disabled or unconfigured"
                    )

                if serialized_data["is_sample"]:
                    if not config.is_type_file:
                        raise NotRunnableAnalyzer(
                            f"{a_name} won't be run because does not support files."
                        )
                    if not config.is_filetype_supported(
                        serialized_data["file_mimetype"]
                    ):
                        raise NotRunnableAnalyzer(
                            f"{a_name} won't be run because mimetype "
                            f"{serialized_data['file_mimetype']} is not supported."
                        )
                else:
                    if not config.is_type_observable:
                        raise NotRunnableAnalyzer(
                            f"{a_name} won't be run because "
                            f"it does not support observable."
                        )

                    if not config.is_observable_type_supported(
                        serialized_data["observable_classification"]
                    ):
                        raise NotRunnableAnalyzer(
                            f"{a_name} won't be run because "
                            f"it does not support observable type "
                            f"{serialized_data['observable_classification']}."
                        )

                if tlp != TLP.WHITE and config.leaks_info:
                    raise NotRunnableAnalyzer(
                        f"{a_name} won't be run because it leaks info externally."
                    )
                if tlp == TLP.RED and config.external_service:
                    raise NotRunnableAnalyzer(
                        f"{a_name} won't be run because you"
                        f" filtered external analyzers."
                    )
            except NotRunnableAnalyzer as e:
                if run_all:
                    # in this case, they are not warnings but
                    # expected and wanted behavior
                    logger.debug(e)
                else:
                    logger.warning(e)
                    self.filter_warnings.append(str(e))
            else:
                cleaned_analyzer_list.append(a_name)

        if len(cleaned_analyzer_list) == 0:
            raise ValidationError(
                {"detail": "No Analyzers can be run after filtering."}
            )
        return cleaned_analyzer_list

    def filter_connectors(self, serialized_data: Dict) -> List[str]:
        # init empty list
        cleaned_connectors_list = []
        selected_connectors = []

        # get values from serializer
        connectors_requested = serialized_data.get("connectors_requested", [])
        tlp = serialized_data.get("tlp", TLP.WHITE).upper()

        # read config
        connector_dataclasses = ConnectorConfig.all()
        all_connector_names = list(connector_dataclasses.keys())

        # run all connectors ?
        run_all = len(connectors_requested) == 0
        if run_all:
            # select all
            selected_connectors.extend(all_connector_names)
        else:
            # select the ones requested
            selected_connectors.extend(connectors_requested)

        for c_name in selected_connectors:
            try:
                cc = connector_dataclasses.get(c_name, None)

                if not cc:
                    if not run_all:
                        raise NotRunnableConnector(
                            f"{c_name} won't run: not available in configuration"
                        )
                    # don't add warning if run_all
                    continue

                if not cc.is_ready_to_use:  # check configured/disabled
                    raise NotRunnableConnector(
                        f"{c_name} won't run: is disabled or unconfigured"
                    )

                if TLP.get_priority(tlp) > TLP.get_priority(
                    cc.maximum_tlp
                ):  # check if job's tlp allows running
                    # e.g. if connector_tlp is GREEN(1),
                    # run for job_tlp WHITE(0) & GREEN(1) only
                    raise NotRunnableConnector(
                        f"{c_name} won't run: "
                        f"job.tlp ('{tlp}') > maximum_tlp ('{cc.maximum_tlp}')"
                    )
            except NotRunnableConnector as e:
                if run_all:
                    # in this case, they are not warnings but
                    # expected and wanted behavior
                    logger.debug(e)
                else:
                    logger.warning(e)
                    self.filter_warnings.append(str(e))
            else:
                cleaned_connectors_list.append(c_name)

        return cleaned_connectors_list

    def filter_analyzers_and_connectors(self, attrs: dict) -> dict:
        attrs["analyzers_to_execute"] = self.filter_analyzers(attrs)
        attrs["connectors_to_execute"] = self.filter_connectors(attrs)
        attrs["warnings"] = self.filter_warnings
        return attrs

    def create(self, validated_data: dict) -> Job:
        # create ``Tag`` objects from tags_labels
        tags_labels = validated_data.pop("tags_labels", None)
        validated_data.pop("warnings")
        tags = [
            Tag.objects.get_or_create(
                label=label, defaults={"color": gen_random_colorhex()}
            )[0]
            for label in tags_labels
        ]

        job = Job.objects.create(**validated_data)
        if tags:
            job.tags.set(tags)

        return job


class JobListSerializer(_AbstractJobViewSerializer):
    """
    Used for ``list()``.
    """

    class Meta:
        model = Job
        exclude = ("file",)


class JobSerializer(_AbstractJobViewSerializer):
    """
    Used for ``retrieve()``
    """

    class Meta:
        model = Job
        exclude = ("file",)

    analyzer_reports = AnalyzerReportSerializer(many=True, read_only=True)
    connector_reports = ConnectorReportSerializer(many=True, read_only=True)
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


class FileAnalysisSerializer(_AbstractJobCreateSerializer):
    """
    ``Job`` model's serializer for File Analysis.
    Used for ``create()``.
    """

    file = rfs.FileField(required=True)
    file_name = rfs.CharField(required=True)
    file_mimetype = rfs.CharField(required=False)
    is_sample = rfs.HiddenField(default=True)

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
            "tags_labels",
        )

    def validate(self, attrs: dict) -> dict:
        attrs = super(FileAnalysisSerializer, self).validate(attrs)
        logger.debug(f"before attrs: {attrs}")
        # calculate ``file_mimetype``
        attrs["file_mimetype"] = calculate_mimetype(attrs["file"], attrs["file_name"])
        # calculate ``md5``
        file_obj = attrs["file"].file
        file_obj.seek(0)
        file_buffer = file_obj.read()
        attrs["md5"] = calculate_md5(file_buffer)
        self.filter_analyzers_and_connectors(attrs)
        logger.debug(f"after attrs: {attrs}")
        return attrs


class MultipleObservableAnalysisSerializer(rfs.ListSerializer):
    """
    ``Job`` model's serializer for Multiple Observable Analysis.
    Used for ``create()``.
    """

    def update(self, instance, validated_data):
        raise NotImplementedError("This serializer does not support update().")

    observables = rfs.ListField(required=True)

    def to_internal_value(self, data):
        ret = []
        errors = []

        for classification, name in data.get("observables"):

            # `deepcopy` here ensures that this code doesn't
            # break even if new fields are added in future
            item = copy.deepcopy(data)

            item.pop("observables", None)
            item["observable_name"] = name
            item["observable_classification"] = classification
            try:
                validated = self.child.run_validation(item)
            except ValidationError as exc:
                errors.append(exc.detail)
            else:
                ret.append(validated)
                errors.append({})

        if any(errors):
            raise ValidationError(errors)

        return ret


class ObservableAnalysisSerializer(_AbstractJobCreateSerializer):
    """
    ``Job`` model's serializer for Observable Analysis.
    Used for ``create()``.
    """

    observable_name = rfs.CharField(required=True)
    observable_classification = rfs.CharField(required=False)
    is_sample = rfs.HiddenField(default=False)

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
            "tags_labels",
        )
        list_serializer_class = MultipleObservableAnalysisSerializer

    def validate(self, attrs: dict) -> dict:
        attrs = super(ObservableAnalysisSerializer, self).validate(attrs)
        logger.debug(f"before attrs: {attrs}")
        # calculate ``observable_classification``
        if not attrs.get("observable_classification", None):
            attrs["observable_classification"] = calculate_observable_classification(
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
        self.filter_analyzers_and_connectors(attrs)
        logger.debug(f"after attrs: {attrs}")
        return attrs


class AnalysisResponseSerializer(rfs.Serializer):
    job_id = rfs.IntegerField()
    status = rfs.CharField()
    warnings = rfs.ListField(required=False)
    analyzers_running = rfs.ListField()
    connectors_running = rfs.ListField()


def multi_result_enveloper(serializer_class, many):
    component_name = "Multi{}{}".format(
        serializer_class.__name__.replace("Serializer", ""),
        "List" if many else "",
    )

    @extend_schema_serializer(many=False, component_name=component_name)
    class EnvelopeSerializer(rfs.Serializer):
        count = rfs.BooleanField()  # No. of items in the results list
        results = serializer_class(many=many)

    return EnvelopeSerializer
