# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from rest_framework import serializers as rfs

from api_app.analyzers_manager.constants import ObservableTypes
from api_app.core.serializers import AbstractConfigSerializer
from api_app.serializers import AnalysisResponseSerializer


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
        child=rfs.ChoiceField(choices=ObservableTypes.values),
        required=False,
        default=[],
    )


class PlaybookAnalysisResponseSerializer(AnalysisResponseSerializer):
    playbooks_running = rfs.ListField()
