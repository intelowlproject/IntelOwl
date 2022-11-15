# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import json
import logging

from django.core import serializers
from rest_framework import serializers as rfs

from api_app.analyzers_manager.constants import AllTypes
from api_app.analyzers_manager.serializers import AnalyzerConfigSerializer
from api_app.connectors_manager.serializers import ConnectorConfigSerializer
from api_app.core.serializers import AbstractConfigSerializer
from api_app.models import Job

from .models import CachedPlaybook

logger = logging.getLogger(__name__)


class PlaybookConfigSerializer(AbstractConfigSerializer):
    """
    Serializer for `playbook_config.json`.
    """

    CONFIG_FILE_NAME = "playbook_config.json"

    config = rfs.DictField(default={})
    secrets = rfs.DictField(default={})
    params = rfs.DictField(default={})
    python_module = rfs.CharField(default="")
    # automatically populated fields
    verification = rfs.DictField(default={})

    # Required fields
    description = rfs.CharField()
    analyzers = rfs.DictField(child=rfs.DictField())
    connectors = rfs.DictField(child=rfs.DictField())

    # Optional Fields
    supports = rfs.ListField(
        child=rfs.ChoiceField(choices=AllTypes.values),
        required=False,
        default=[],
    )

    @classmethod
    def _cached_playbooks(cls) -> dict:
        """
        Returns config file as `dict`.
        """
        config = super()._read_config()
        # print(config)
        cached_playbooks = CachedPlaybook.objects.all()
        cached_serialized_playbooks = serializers.serialize(
            "json", [obj for obj in cached_playbooks]
        )
        cached_playbooks_model_json = json.loads(cached_serialized_playbooks)
        if len(cached_playbooks_model_json) == 0:
            # this is for when no playbooks are cached
            return config

        cached_playbooks_final = {}
        for playbook in cached_playbooks_model_json:
            cached_playbooks_final[playbook["pk"]] = playbook["fields"]

        return cached_playbooks_final

    @classmethod
    def output_with_cached_playbooks(cls) -> dict:
        original_config_dict = cls.read_and_verify_config()
        config_dict = cls._cached_playbooks()
        serializer_errors = {}
        for key, config in config_dict.items():
            new_config = {"name": key, **config}
            serializer = cls(data=new_config)  # lgtm [py/call-to-non-callable]
            if serializer.is_valid():
                config_dict[key] = serializer.data
            else:
                serializer_errors[key] = serializer.errors

        if bool(serializer_errors):
            logger.error(f"{cls.__name__} serializer failed: {serializer_errors}")
            raise rfs.ValidationError(serializer_errors)

        config_dict = config_dict | original_config_dict
        return config_dict


class CachedPlaybooksSerializer(rfs.ModelSerializer):
    job_id = rfs.IntegerField()
    name = rfs.CharField(max_length=225)
    description = rfs.CharField(max_length=225)

    class Meta:
        model = CachedPlaybook
        fields = (
            "name",
            "description",
            "analyzers",
            "connectors",
            "supports",
            "disabled",
            "job_id",
        )

    def validate(self, attrs: dict) -> dict:
        attrs = super().validate(attrs)
        print(attrs)
        playbook_name = attrs["name"].replace(" ", "_").upper()
        job_id = attrs.get("job_id")

        # it might be safer for us to
        # consider organisational permissions
        # for accessing jobs and saving them as
        # playbooks.
        job = Job.objects.get(pk=job_id)

        analyzers_used = job.analyzers_to_execute
        connectors_used = job.connectors_to_execute

        analyzers = {analyzer: {} for analyzer in analyzers_used}
        connectors = {connector: {} for connector in connectors_used}

        supports = []
        existing_playbooks = PlaybookConfigSerializer.output_with_cached_playbooks()

        existing_playbook = existing_playbooks.get(playbook_name, {})

        if existing_playbook != {}:
            raise rfs.ValidationError("Another playbook exists with that name.")

        analyzer_config = AnalyzerConfigSerializer.read_and_verify_config()
        for analyzer_ in analyzers:
            analyzer_checked = analyzer_config.get(analyzer_)
            if analyzer_checked is None:
                logger.info(f"Invalid analyzer {analyzer_}")
            type_ = analyzer_checked.get("type")
            if type_ == "file":
                if type_ in supports:
                    continue
                supports.append(type_)
            else:
                observable_supported = analyzer_checked.get("observable_supported")
                for observable_type in observable_supported:
                    if observable_type not in supports:
                        supports.append(observable_type)

        connector_config = ConnectorConfigSerializer.read_and_verify_config()
        for connector_ in connectors:
            connector_checked = connector_config.get(connector_)
            if connector_checked is None:
                logger.info(f"Invalid connector {connector_}")

        attrs["analyzers"] = analyzers
        attrs["connectors"] = connectors
        attrs["supports"] = supports
        attrs["name"] = playbook_name

        return attrs

    def create(self, validated_data: dict) -> CachedPlaybook:
        playbook_name = validated_data.get("name")
        analyzers = validated_data.get("analyzers")
        connectors = validated_data.get("connectors")
        supports = validated_data.get("supports")
        playbook_description = validated_data.get("description")
        job_id = validated_data.get("job_id")
        disabled = validated_data.get("disabled")

        job = Job.objects.filter(pk=job_id).first()

        if job is None:
            raise rfs.ValidationError(f"Job of {job_id} doesn't exist.")

        playbook = self.Meta.model.objects.create(
            name=playbook_name,
            analyzers={analyzer: {} for analyzer in analyzers},
            connectors={connector: {} for connector in connectors},
            supports=supports,
            description=playbook_description,
            job=job,
            disabled=disabled if type(disabled) == bool else False,
        )

        return playbook
