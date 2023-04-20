# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
import abc
import logging
from enum import Enum
from typing import Any, Dict, List, Type, Union

from django.conf import settings
from django.db.models import QuerySet

from api_app.core.classes import Plugin
from api_app.visualizers_manager.enums import VisualizableColor, VisualizableIcon
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
    def attributes(self) -> List[str]:
        return ["hide_if_empty", "disable_if_empty"]

    @property
    @abc.abstractmethod
    def type(self):
        raise NotImplementedError()

    def __bool__(self):
        return True

    def to_dict(self) -> Dict:
        if not self:
            return {}

        result = {attr: getattr(self, attr) for attr in self.attributes}
        for key, value in result.items():
            if isinstance(value, VisualizableObject):
                result[key] = value.to_dict()

        result["type"] = self.type
        return result


class VisualizableBase(VisualizableObject):
    def __init__(
        self,
        value: Any = "",
        color: VisualizableColor = VisualizableColor.TRANSPARENT,
        link: str = "",
        classname: str = "",
        hide_if_empty: bool = False,
        disable_if_empty: bool = True,
        # you can use an element of the enum or an iso3166 alpha2 code (for flags)
        icon: Union[VisualizableIcon, str] = VisualizableIcon.EMPTY,
    ):
        super().__init__(hide_if_empty, disable_if_empty)
        self.value = value
        self.color = color
        self.link = link
        self.classname = classname
        self.icon = icon

    @property
    def attributes(self) -> List[str]:
        return super().attributes + ["value", "color", "link", "classname", "icon"]

    @property
    def type(self) -> str:
        return "base"

    def __bool__(self):
        return bool(self.value) or bool(self.icon)

    def to_dict(self) -> Dict:
        result = super().to_dict()
        if result:
            for enum_key in ["color", "icon"]:
                if isinstance(result[enum_key], Enum):
                    result[enum_key] = str(result[enum_key].value)
                else:  # some icon codes are in camelcase
                    result[enum_key] = result[enum_key].lower()

        return result


class VisualizableTitle(VisualizableObject):
    def __init__(
        self,
        title: VisualizableBase,
        value: VisualizableBase,
        hide_if_empty: bool = False,
        disable_if_empty: bool = True,
    ):
        super().__init__(hide_if_empty, disable_if_empty)
        self.title = title
        self.value = value

    @property
    def attributes(self) -> List[str]:
        return super().attributes + ["title", "value"]

    @property
    def type(self) -> str:
        return "title"


class VisualizableBool(VisualizableBase):
    def __init__(
        self,
        name: str,
        value: bool,
        *args,
        pill: bool = True,
        color: VisualizableColor = VisualizableColor.DANGER,
        **kwargs,
    ):
        super().__init__(*args, color=color, value=value, **kwargs)
        self.name = name
        self.pill = pill

    def __bool__(self):
        return bool(self.name)

    @property
    def attributes(self) -> List[str]:
        return super().attributes + ["name", "pill"]

    @property
    def type(self) -> str:
        return "bool"

    def to_dict(self) -> Dict:
        result = super().to_dict()
        # bool does not support icon at the moment
        result.pop("icon", None)
        return result


class VisualizableListMixin:
    def to_dict(self) -> Dict:
        result = super().to_dict()  # noqa
        values: List[VisualizableObject] = result.pop("value", [])
        if any(x for x in values):
            result["values"] = [val.to_dict() for val in values]
        else:
            result["values"] = []
        return result


class VisualizableVerticalList(VisualizableListMixin, VisualizableBase):
    def __init__(
        self,
        name: str,
        value: List[VisualizableObject],
        *args,
        open: bool = False,  # noqa
        max_element_number: int = -1,
        add_count_in_title: bool = True,
        **kwargs,
    ):
        elements_number = len(value)
        filtered_element_list = value
        if max_element_number > 0:
            filtered_element_list = filtered_element_list[:max_element_number]
            exceeding_elements_number = elements_number - max_element_number
            if exceeding_elements_number > 0:
                filtered_element_list.append(
                    VisualizableBase(
                        f"{exceeding_elements_number} more elements: consult raw data"
                    )
                )
        super().__init__(value=filtered_element_list, *args, **kwargs)
        self.name = name
        if add_count_in_title:
            self.name = f"{self.name} ({elements_number})"
        self.open = open


class VisualizableHorizontalList(VisualizableListMixin, VisualizableObject):
    def __init__(
        self,
        value: List[VisualizableObject],
        *args,
        **kwargs,
    ):
        super().__init__(*args, **kwargs)
        self.value = value

    @property
    def attributes(self) -> List[str]:
        return super().attributes + ["value"]

    @property
    def type(self) -> str:
        return "horizontal_list"


class VisualizableLevel:
    def __init__(self):
        self._levels = {}

    def add_level(self, level: int, horizontal_list: VisualizableHorizontalList):
        self._levels[level] = horizontal_list

    def to_dict(self) -> List[Dict]:
        return [
            {"level": level, "elements": hl.to_dict()}
            for level, hl in self._levels.items()
        ]

    def update_level(self, level: int, *elements):
        if level not in self._levels:
            raise KeyError(f"Level {level} was not defined")
        self._levels[level].value.extend(list(elements))


class Visualizer(Plugin, metaclass=abc.ABCMeta):
    Color = VisualizableColor
    Icon = VisualizableIcon

    Base = VisualizableBase
    Title = VisualizableTitle
    Bool = VisualizableBool
    VList = VisualizableVerticalList
    HList = VisualizableHorizontalList

    Level = VisualizableLevel

    @classmethod
    @property
    def python_base_path(cls):
        return settings.BASE_VISUALIZER_PYTHON_PATH

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
        if not isinstance(self.report.report, list):
            raise VisualizerRunException(
                f"Report has not correct type: {type(self.report.report)}"
            )
        logger.info(f"FINISHED visualizer: {self.__repr__()}")

    def analyzer_reports(self) -> QuerySet:
        from api_app.analyzers_manager.models import AnalyzerReport

        self._config: VisualizerConfig
        configs = self._config.analyzers.all()
        queryset = AnalyzerReport.objects.filter(job=self._job)
        if configs:
            queryset = queryset.filter(config__in=configs)
        return queryset

    def connector_reports(self) -> QuerySet:
        from api_app.connectors_manager.models import ConnectorReport

        self._config: VisualizerConfig
        configs = self._config.connectors.all()

        queryset = ConnectorReport.objects.filter(job=self._job)
        if configs:
            queryset = queryset.filter(config__in=configs)
        return queryset
