# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
import copy
import json
import logging
from typing import Dict, List

from django.http import QueryDict
from drf_spectacular.utils import extend_schema_serializer
from durin.serializers import UserSerializer
from rest_framework import serializers as rfs
from rest_framework.exceptions import PermissionDenied, ValidationError
from rest_framework.fields import empty

from certego_saas.apps.organization.membership import Membership

# from django.contrib.auth import get_user_model
from certego_saas.apps.organization.organization import Organization
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
from .models import TLP, Job, PluginConfig, Tag

logger = logging.getLogger(__name__)

__all__ = [
    "TagSerializer",
    "JobAvailabilitySerializer",
    "JobListSerializer",
    "JobSerializer",
    "FileAnalysisSerializer",
    "ObservableAnalysisSerializer",
    "AnalysisResponseSerializer",
    "MultipleFileAnalysisSerializer",
    "MultipleObservableAnalysisSerializer",
    "multi_result_enveloper",
    "PluginConfigSerializer",
]


# User = get_user_model()


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
        self.filter_analyzers_and_connectors(attrs)
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

                if (
                    not config.is_ready_to_use
                    or self.context["plugin_states"]
                    .filter(plugin_name=a_name, disabled=True)
                    .exists()
                ):
                    raise NotRunnableAnalyzer(
                        f"{a_name} won't run: is disabled or unconfigured"
                    )

                if tlp != TLP.WHITE and config.leaks_info:
                    raise NotRunnableAnalyzer(
                        f"{a_name} won't be run because it leaks info externally."
                    )
                if tlp == TLP.RED and config.external_service:
                    raise NotRunnableAnalyzer(
                        f"{a_name} won't be run because you"
                        " filtered external analyzers."
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
        self.filter_warnings = []
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
                errors.append({})

        if any(errors):
            raise ValidationError(errors)

        return ret


class FileAnalysisSerializer(_AbstractJobCreateSerializer):
    """
    ``Job`` model's serializer for File Analysis.
    Used for ``create()``.
    """

    file = rfs.FileField(required=True)
    file_name = rfs.CharField(required=False)
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
        list_serializer_class = MultipleFileAnalysisSerializer

    def validate(self, attrs: dict) -> dict:
        logger.debug(f"before attrs: {attrs}")
        # calculate ``file_mimetype``
        if "file_name" not in attrs:
            attrs["file_name"] = attrs["file"].name
        attrs["file_mimetype"] = calculate_mimetype(attrs["file"], attrs["file_name"])
        # calculate ``md5``
        file_obj = attrs["file"].file
        file_obj.seek(0)
        file_buffer = file_obj.read()
        attrs["md5"] = calculate_md5(file_buffer)
        attrs = super().validate(attrs)
        logger.debug(f"after attrs: {attrs}")
        return attrs

    def filter_analyzers(self, serialized_data: Dict) -> List[str]:
        cleaned_analyzer_list = []

        # get values from serializer
        partially_filtered_analyzers = super().filter_analyzers(serialized_data)

        # read config
        analyzer_dataclasses = AnalyzerConfig.all()

        run_all = len(serialized_data.get("analyzers_requested", [])) == 0

        for a_name in partially_filtered_analyzers:
            try:
                config = analyzer_dataclasses.get(a_name, None)
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
                    raise ValidationError(
                        f"{a_name} won't be run because is_sample is False."
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

        for classification, name in data.get("observables", []):

            # `deepcopy` here ensures that this code doesn't
            # break even if new fields are added in future
            item = copy.deepcopy(data)

            item.pop("observables", None)
            item["observable_name"] = name
            if classification:
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
        attrs = super().validate(attrs)
        logger.debug(f"after attrs: {attrs}")
        return attrs

    def filter_analyzers(self, serialized_data: Dict) -> List[str]:
        cleaned_analyzer_list = []

        # get values from serializer
        partially_filtered_analyzers = super().filter_analyzers(serialized_data)

        # read config
        analyzer_dataclasses = AnalyzerConfig.all()

        run_all = len(serialized_data.get("analyzers_requested", [])) == 0

        for a_name in partially_filtered_analyzers:
            try:
                config = analyzer_dataclasses.get(a_name, None)
                if serialized_data["is_sample"]:
                    raise ValidationError(
                        f"{a_name} won't be run because is_sample is True."
                    )
                else:
                    if not config.is_type_observable:
                        raise NotRunnableAnalyzer(
                            f"{a_name} won't be run because "
                            "it does not support observable."
                        )

                    if not config.is_observable_type_supported(
                        serialized_data["observable_classification"]
                    ):
                        raise NotRunnableAnalyzer(
                            f"{a_name} won't be run because "
                            "it does not support observable type "
                            f"{serialized_data['observable_classification']}."
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


class AnalysisResponseSerializer(rfs.Serializer):
    job_id = rfs.IntegerField()
    status = rfs.CharField()
    warnings = rfs.ListField(required=False)
    analyzers_running = rfs.ListField()
    connectors_running = rfs.ListField()


def multi_result_enveloper(serializer_class, many):
    component_name = (
        f'Multi{serializer_class.__name__.replace("Serializer", "")}'
        f'{"List" if many else ""}'
    )

    @extend_schema_serializer(many=False, component_name=component_name)
    class EnvelopeSerializer(rfs.Serializer):
        count = rfs.BooleanField()  # No. of items in the results list
        results = serializer_class(many=many)

    return EnvelopeSerializer


class PluginConfigSerializer(rfs.ModelSerializer):
    class CustomJSONField(rfs.JSONField):
        def run_validation(self, data=empty):
            value = super().run_validation(data)
            try:
                return json.loads(value)
            except json.JSONDecodeError:
                raise ValidationError("Value is not JSON-compliant.")

        def to_representation(self, value):
            return json.dumps(super().to_representation(value))

    # certego_saas does not expose organization.id to frontend
    organization = rfs.SlugRelatedField(
        allow_null=True,
        slug_field="name",
        queryset=Organization.objects.all(),
        required=False,
    )

    value = CustomJSONField()

    class Meta:
        model = PluginConfig
        fields = rfs.ALL_FIELDS

    def validate(self, attrs):
        super().validate(attrs)

        # check if owner is admin of organization
        if attrs.get("organization", None):
            # check if the user is owner of the organization
            membership = Membership.objects.filter(
                user=attrs.get("owner"),
                organization=attrs.get("organization"),
                is_owner=True,
            )
            if not membership.exists():
                logger.warning(
                    f"User {attrs.get('owner')} is not owner of "
                    f"organization {attrs.get('organization')}."
                )
                raise PermissionDenied("User is not owner of the organization.")

        if attrs["type"] == PluginConfig.PluginType.ANALYZER:
            config = AnalyzerConfig
            category = "Analyzer"
        elif attrs["type"] == PluginConfig.PluginType.CONNECTOR:
            config = ConnectorConfig
            category = "Connector"
        else:
            logger.error(f"Unknown custom config type: {attrs['type']}")
            raise ValidationError("Invalid type.")

        if attrs["plugin_name"] not in config.all():
            raise ValidationError(f"{category} {attrs['plugin_name']} does not exist.")

        if attrs["config_type"] == PluginConfig.ConfigType.PARAMETER:
            if attrs["attribute"] not in config.all()[attrs["plugin_name"]].params:
                raise ValidationError(
                    f"{category} {attrs['plugin_name']} does not "
                    f"have parameter {attrs['attribute']}."
                )
        elif attrs["config_type"] == PluginConfig.ConfigType.SECRET:
            if attrs["attribute"] not in config.all()[attrs["plugin_name"]].secrets:
                raise ValidationError(
                    f"{category} {attrs['plugin_name']} does not "
                    f"have secret {attrs['attribute']}."
                )
        # Check if the type of value is valid for the attribute.
        expected_type = (
            type(config.all()[attrs["plugin_name"]].params[attrs["attribute"]].value)
            if attrs["config_type"] == PluginConfig.ConfigType.PARAMETER
            else str
        )
        if not isinstance(
            attrs["value"],
            expected_type,
        ):
            raise ValidationError(
                f"{category} {attrs['plugin_name']} attribute "
                f"{attrs['attribute']} has wrong type "
                f"{type(attrs['value']).__name__}. Expected: "
                f"{expected_type.__name__}."
            )

        inclusion_params = attrs.copy()
        exclusion_params = {}
        inclusion_params.pop("value")
        if "organization" not in inclusion_params:
            inclusion_params["organization__isnull"] = True
        if self.instance is not None:
            exclusion_params["id"] = self.instance.id
        if (
            PluginConfig.objects.filter(**inclusion_params)
            .exclude(**exclusion_params)
            .exists()
        ):
            raise ValidationError(
                f"{category} {attrs['plugin_name']} "
                f"{self} attribute {attrs['attribute']} already exists."
            )
        return attrs
