# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import dataclasses
import logging
import typing

from django.conf import settings

from api_app.core.dataclasses import AbstractConfig

from .serializers import VisualizerConfigSerializer

__all__ = ["VisualizerConfig"]

from ..core.models import AbstractReport

logger = logging.getLogger(__name__)


@dataclasses.dataclass
class VisualizerConfig(AbstractConfig):
    analyzers: typing.List[str]
    connectors: typing.List[str]

    @classmethod
    def _get_report_model(cls) -> typing.Type[AbstractReport]:
        from api_app.visualizers_manager.models import VisualizerReport

        return VisualizerReport

    @classmethod
    def _get_serializer_class(cls) -> typing.Type[VisualizerConfigSerializer]:
        return VisualizerConfigSerializer

    def get_full_import_path(self) -> str:
        return f"{settings.BASE_VISUALIZER_PYTHON_PATH}.{self.python_module}"
