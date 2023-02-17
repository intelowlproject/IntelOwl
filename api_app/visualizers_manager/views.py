# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging
import typing

from drf_spectacular.utils import extend_schema as add_docs
from drf_spectacular.utils import inline_serializer
from rest_framework import serializers as rfs

from api_app.core.views import PluginListAPI
from api_app.visualizers_manager.serializers import VisualizerConfigSerializer

logger = logging.getLogger(__name__)


__all__ = [
    "VisualizerListAPI",
]


class VisualizerListAPI(PluginListAPI):
    @property
    def serializer_class(self) -> typing.Type[VisualizerConfigSerializer]:
        return VisualizerConfigSerializer

    @add_docs(
        description="Get and parse the `visualizer_config.json` file",
        parameters=[],
        responses={
            200: VisualizerConfigSerializer,
            500: inline_serializer(
                name="GetVisualizerConfigsFailedResponse",
                fields={"error": rfs.StringRelatedField()},
            ),
        },
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)
