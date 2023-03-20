# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
import abc
import logging
from typing import Any, Dict, List, Type

from django.db.models import QuerySet

from api_app.core.classes import Plugin
from api_app.visualizers_manager.enums import Color
from api_app.visualizers_manager.exceptions import (
    VisualizerConfigurationException,
    VisualizerRunException,
)
from api_app.visualizers_manager.models import VisualizerConfig, VisualizerReport

logger = logging.getLogger(__name__)


class VisualizableObject:
    def __init__(self, hide_if_empty: bool = False, disable_if_empty: bool = True):
        self.hide_if_empty = hide_if_empty
        self.disable_if_empty = disable_if_empty

    @property
    @abc.abstractmethod
    def type(self):
        raise NotImplementedError()

    def to_dict(self) -> Dict:
        result = vars(self)
        result["type"] = self.type
        return result


class VisuablizableBase(VisualizableObject):
    def __init__(
        self,
        value: Any,
        color: Color = Color.TRANSPARENT,
        link: str = "",
        classname: str = "",
        hide_if_empty: bool = False,
        disable_if_empty: bool = True,
    ):
        super().__init__(hide_if_empty, disable_if_empty)
        self.value = value
        self.color = color
        self.link = link
        self.classname = classname

    @property
    def type(self) -> str:
        return "base"

    def to_dict(self) -> Dict:
        result = super().to_dict()
        result["color"] = str(result["color"])
        return result


class VisualizableTitle(VisualizableObject):
    def __init__(
        self,
        title: VisuablizableBase,
        value: VisuablizableBase,
        hide_if_empty: bool = False,
        disable_if_empty: bool = True,
    ):
        super().__init__(hide_if_empty, disable_if_empty)
        self.title = title
        self.value = value

    def to_dict(self) -> Dict:
        res = super().to_dict()
        for attr in ["title", "value"]:
            obj: VisuablizableBase = res.pop(attr)
            for key, value in obj.to_dict().items():
                if key in ["type", "hide_if_empty", "disable_if_empty"]:
                    continue
                res[f"{attr}_{key}"] = value
        return res

    @property
    def type(self) -> str:
        return "title"


class VisualizableBool(VisuablizableBase):
    def __init__(
        self,
        name: str,
        value: bool,
        *args,
        pill: bool = True,
        color: Color = Color.DANGER,
        **kwargs,
    ):
        super().__init__(*args, color=color, value=value, **kwargs)
        self.name = name
        self.pill = pill

    @property
    def type(self) -> str:
        return "bool"


class VisualizableIcon(VisuablizableBase):
    def __init__(self, name:str, value: str, color: Color = Color.DARK, *args, **kwargs):
        super().__init__(*args, value=value, color=color, **kwargs)
        self.name = name
        self.value = value

    @property
    def type(self) -> str:
        return "icon"


class VisualizableList(VisuablizableBase):
    def __init__(
        self,
        name: str,
        value: List[VisualizableObject],
        *args,
        open: bool = False,
        **kwargs,
    ):
        super().__init__(value=value, *args, **kwargs)
        self.name = name
        self.open = open

    @property
    def type(self) -> str:
        return "list"

    def to_dict(self) -> Dict:
        result = super().to_dict()
        values: List[VisualizableObject] = result.pop("value")
        result["values"] = [val.to_dict() for val in values]
        return result


class VisualizableLevel:
    def __init__(self, level: int, elements: List[VisualizableObject]):
        self.level = level
        self.elements = elements

    def to_dict(self):
        return {
            "level": self.level,
            "elements": [element.to_dict() for element in self.elements],
        }


class Visualizer(Plugin, metaclass=abc.ABCMeta):
    Color = Color
    Base = VisuablizableBase
    Title = VisualizableTitle
    Bool = VisualizableBool
    Icon = VisualizableIcon
    List = VisualizableList
    Level = VisualizableLevel

    @property
    def visualizer_name(self) -> str:
        return self._config.name

    @classmethod
    @property
    def report_model(cls):
        return VisualizerReport

    @classmethod
    @property
    def config_model(cls) -> Type[VisualizerConfig]:
        return VisualizerConfig

    def get_exceptions_to_catch(self) -> list:
        return [
            VisualizerConfigurationException,
            VisualizerRunException,
        ]

    def get_error_message(self, err, is_base_err=False):
        return (
            f"{self.__repr__()}."
            f" {'Unexpected error' if is_base_err else 'Connector error'}: '{err}'"
        )

    def before_run(self, *args, **kwargs):
        logger.info(f"STARTED visualizer: {self.__repr__()}")

    def after_run(self):
        if not isinstance(self.report.report, list) and not all(
            isinstance(x, VisualizableLevel) for x in self.report.report
        ):
            raise VisualizerRunException("Report has not correct type")
        logger.info(f"FINISHED visualizer: {self.__repr__()}")

    def analyzer_reports(self) -> QuerySet:
        from api_app.analyzers_manager.models import AnalyzerReport

        self._config: VisualizerConfig
        return AnalyzerReport.objects.filter(
            config__in=self._config.analyzers.all(), job=self._job
        )

    def connector_reports(self) -> QuerySet:
        from api_app.connectors_manager.models import ConnectorReport

        self._config: VisualizerConfig
        return ConnectorReport.objects.filter(
            config__in=self._config.connectors.all(), job=self._job
        )
