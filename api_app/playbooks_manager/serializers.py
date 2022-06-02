# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.utils.module_loading import import_string
from rest_framework import serializers as rfs

from api_app.analyzers_manager.constants import ObservableTypes

from api_app.core.serializers import AbstractConfigSerializer
from api_app.models import TLP



class PlaybookConfigSerializer(AbstractConfigSerializer):
    """
        Serializer for `playbook_config.json`.
    """
    CONFIG_FILE_NAME = "playbook_config.json"

    config = {}
    params = {}
    secrets = {}
    python_module = ""
    verification = {}
    
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



