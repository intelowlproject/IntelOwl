# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
from typing import Type

from api_app.visualizers_manager.models import VisualizerConfig
from tests import CustomViewSetTestCase
from tests.api_app.test_views import AbstractConfigViewSetTestCaseMixin


class VisualizerConfigViewSetTestCase(
    AbstractConfigViewSetTestCaseMixin, CustomViewSetTestCase
):
    URL = "/api/visualizer"

    @classmethod
    @property
    def model_class(cls) -> Type[VisualizerConfig]:
        return VisualizerConfig
