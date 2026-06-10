# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import json

from rest_framework import serializers


class ToolResultSerializer(serializers.Serializer):
    """Base envelope for agent-tool output: an always-present `errors` list plus a payload.

    A LangChain tool must return a string (it is fed back to the model as the tool-call
    observation), so `to_json()` renders the serialized envelope to a JSON string.
    """

    errors = serializers.ListField(child=serializers.CharField(), default=list)

    def to_json(self) -> str:
        return json.dumps(self.data, indent=2)
