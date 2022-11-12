# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging

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
            "default",
            "job_id",
        )

    def validate(self, attrs: dict) -> dict:
        attrs = super().validate(attrs)
        playbook_name = attrs.get("name")

        try:
            job_id = attrs.get("job_id")
        except Exception as e:
            rfs.ValidationError(e)

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
        existing_playbooks = PlaybookConfigSerializer._read_config()
        existing_playbooks.get(playbook_name, None)
        if existing_playbooks is not None:
            rfs.ValidationError("Another playbook exists with that name.")
        analyzer_config = AnalyzerConfigSerializer.read_and_verify_config()
        for analyzer_ in analyzers:
            analyzer_checked = analyzer_config.get(analyzer_)
            if analyzer_checked is None:
                # rfs.ValidationError(f"Invalid analyzer {analyzer_}")
                logger.log(f"Invalid analyzer {analyzer_}")
            type_ = analyzer_checked.get("type")
            if type_ == "file":
                supports.append(type_)
            else:
                observable_supported = analyzer_checked.get("observable_supported")
                supports.extend(observable_supported)

        connector_config = ConnectorConfigSerializer.read_and_verify_config()
        for connector_ in connectors:
            connector_checked = connector_config.get(connector_)
            if connector_checked is None:
                rfs.ValidationError(f"Invalid connector {connector_}")
        attrs["analyzers"] = analyzers
        attrs["connectors"] = connectors
        attrs["supports"] = supports
        attrs["name"] = playbook_name.replace(" ", "_").upper()
        return attrs

    def create(self, validated_data: dict) -> CachedPlaybook:
        playbook_name = validated_data.get("playbook_name")
        analyzers = validated_data.get("analyzers")
        connectors = validated_data.get("connectors")
        supports = validated_data.get("supports")
        playbook_description = validated_data.get("description")

        playbook = self.Meta.model.objects.create(
            name=playbook_name,
            analyzers={analyzer: {} for analyzer in analyzers},
            connectors={connector: {} for connector in connectors},
            supports=supports,
            description=playbook_description,
        )

        return playbook
