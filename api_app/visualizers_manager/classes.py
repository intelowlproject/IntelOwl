# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
import abc
import logging
from enum import Enum
from typing import Any, Dict, List, Tuple, Type, Union

from django.db.models import QuerySet

from api_app.choices import PythonModuleBasePaths
from api_app.classes import Plugin
from api_app.models import AbstractReport
from api_app.visualizers_manager.enums import (
    VisualizableAlignment,
    VisualizableColor,
    VisualizableIcon,
    VisualizableLevelSize,
    VisualizableSize,
)
from api_app.visualizers_manager.exceptions import (
    VisualizerConfigurationException,
    VisualizerRunException,
)
from api_app.visualizers_manager.models import VisualizerConfig, VisualizerReport

logger = logging.getLogger(__name__)


class VisualizableObject:
    def __init__(
        self,
        size: VisualizableSize = VisualizableSize.S_AUTO,
        alignment: VisualizableAlignment = VisualizableAlignment.AROUND,
        disable: bool = True,
    ):
        self.size = size
        self.alignment = alignment
        self.disable = disable

    @property
    def attributes(self) -> List[str]:
        return ["size", "alignment", "disable"]

    @property
    @abc.abstractmethod
    def type(self):
        raise NotImplementedError()

    def __bool__(self):
        return True

    def to_dict(self) -> Dict:
        if not self and not self.disable:
            return {}

        result = {attr: getattr(self, attr) for attr in self.attributes}
        for key, value in result.items():
            if isinstance(value, VisualizableObject):
                result[key] = value.to_dict()
            elif isinstance(value, Enum):
                result[key] = value.value

        result["type"] = self.type
        return result


class VisualizableBase(VisualizableObject):
    def __init__(
        self,
        value: Any = "",
        size: VisualizableSize = VisualizableSize.S_AUTO,
        alignment: VisualizableAlignment = VisualizableAlignment.CENTER,
        color: VisualizableColor = VisualizableColor.TRANSPARENT,
        link: str = "",
        # you can use an element of the enum or an iso3166 alpha2 code (for flags)
        icon: Union[VisualizableIcon, str] = VisualizableIcon.EMPTY,
        bold: bool = False,
        italic: bool = False,
        disable: bool = True,
        copy_text: str = "",
        description: str = "",
    ):
        super().__init__(size, alignment, disable)
        self.value = value
        self.color = color
        self.link = link
        self.icon = icon
        self.bold = bold
        self.italic = italic
        self.copy_text = copy_text or value
        self.description = description

    @property
    def attributes(self) -> List[str]:
        return super().attributes + [
            "value",
            "color",
            "link",
            "icon",
            "bold",
            "italic",
            "copy_text",
            "description",
        ]

    @property
    def type(self) -> str:
        return "base"

    def __bool__(self):
        return bool(self.value) or bool(self.icon)


class VisualizableTitle(VisualizableObject):
    def __init__(
        self,
        title: VisualizableBase,
        value: VisualizableObject,
        alignment: VisualizableAlignment = VisualizableAlignment.CENTER,
        size: VisualizableSize = VisualizableSize.S_AUTO,
        disable: bool = True,
    ):
        super().__init__(size, alignment, disable)
        self.title = title
        self.value = value
        if self.disable != self.title.disable or self.disable != self.value.disable:
            logger.warning(
                "Each part of the title should be disabled. "
                f"Forcing all to disable={self.disable}"
            )
            self.title.disable = self.disable
            self.value.disable = self.disable

    @property
    def attributes(self) -> List[str]:
        return super().attributes + ["title", "value"]

    @property
    def type(self) -> str:
        return "title"


class VisualizableBool(VisualizableBase):
    def __init__(
        self,
        value: str,
        disable: bool,
        *args,
        size: VisualizableSize = VisualizableSize.S_AUTO,
        color: VisualizableColor = VisualizableColor.DANGER,
        **kwargs,
    ):
        super().__init__(
            *args, value=value, size=size, color=color, disable=disable, **kwargs
        )

    def __bool__(self):
        return bool(self.value)

    @property
    def type(self) -> str:
        return "bool"

    def to_dict(self) -> Dict:
        result = super().to_dict()
        # bool does not support bold because the default is bold
        result.pop("bold", None)
        # bool does not support alignment: it's a stand alone component
        result.pop("alignment", None)
        return result


class VisualizableListMixin:
    def to_dict(self) -> Dict:
        result = super().to_dict()  # noqa
        values: List[VisualizableObject] = result.pop("value", [])
        if any(x for x in values):
            result["values"] = [val.to_dict() for val in values if val is not None]
        else:
            result["values"] = []
        return result


class VisualizableVerticalList(VisualizableListMixin, VisualizableObject):
    def __init__(
        self,
        name: VisualizableBase,
        value: List[VisualizableObject],
        start_open: bool = False,  # noqa
        add_count_in_title: bool = True,
        fill_empty: bool = True,
        alignment: VisualizableAlignment = VisualizableAlignment.CENTER,
        size: VisualizableSize = VisualizableSize.S_AUTO,
        disable: bool = True,
        max_elements_number: int = -1,
        report: AbstractReport = None,
    ):
        super().__init__(
            size=size,
            alignment=alignment,
            disable=disable,
        )
        if add_count_in_title:
            name.value += f" ({len(value)})"
        for v in value:
            if isinstance(v, str):
                raise TypeError(
                    f"value {v} should be a VisualizableObject and not a string"
                )
        if fill_empty and not value:
            value = [VisualizableBase(value="no data available", disable=False)]
        self.value = value
        self.name = name
        self.add_count_in_title = add_count_in_title
        self.start_open = start_open
        self.max_elements_number = max_elements_number
        self.report = report

    @property
    def attributes(self) -> List[str]:
        return super().attributes + ["name", "start_open", "value"]

    def __bool__(self):
        return True

    @property
    def more_elements_object(self) -> VisualizableBase:
        link = ""
        description = ""
        disable = True
        if self.report:
            link = f"{self.report.job.url}/raw/{self.report.config.plugin_name.lower()}"
            description = (
                f"Inspect {self.report.config.name} "
                f"{self.report.config.plugin_name.lower()} to view all the results."
            )
            disable = False
        return VisualizableBase(
            value="...",
            bold=True,
            link=link,
            description=description,
            disable=disable,
        )

    def to_dict(self) -> Dict:
        result = super().to_dict()
        if self and self.max_elements_number > 0:
            current_elements_number = len(result["values"])
            result["values"] = result["values"][: self.max_elements_number]
            # if there are some elements that i'm not displaying
            if current_elements_number - self.max_elements_number > 0:
                result["values"].append(self.more_elements_object.to_dict())

        return result

    @property
    def type(self) -> str:
        return "vertical_list"


class VisualizableHorizontalList(VisualizableListMixin, VisualizableObject):
    def __init__(
        self,
        value: List[VisualizableObject],
        alignment: VisualizableAlignment = VisualizableAlignment.AROUND,
    ):
        super().__init__(alignment=alignment, disable=False)
        self.value = value

    @property
    def attributes(self) -> List[str]:
        return super().attributes + ["value"]

    @property
    def type(self) -> str:
        return "horizontal_list"

    def to_dict(self) -> Dict:
        result = super().to_dict()
        # currently hlist doesn't support disable and size
        result.pop("disable")
        result.pop("size")
        return result


class VisualizableLevel:
    def __init__(
        self,
        position: int,
        size: VisualizableLevelSize = VisualizableLevelSize.S_6,
        horizontal_list: VisualizableHorizontalList = VisualizableHorizontalList(
            value=[]
        ),
    ):
        self._position = position
        self._size = size
        self._horizontal_list = horizontal_list

    def to_dict(self):
        return {
            "level_position": self._position,
            "level_size": self._size.value,
            "elements": self._horizontal_list.to_dict(),
        }


class VisualizablePage:
    def __init__(self, name: str = None):
        self._levels = []
        self.name = name

    def add_level(self, level: VisualizableLevel):
        self._levels.append(level)

    def to_dict(self) -> Tuple[str, List[Dict]]:
        return self.name, [level.to_dict() for level in self._levels]


class Visualizer(Plugin, metaclass=abc.ABCMeta):
    Size = VisualizableSize
    Color = VisualizableColor
    Icon = VisualizableIcon
    Alignment = VisualizableAlignment

    Base = VisualizableBase
    Title = VisualizableTitle
    Bool = VisualizableBool
    VList = VisualizableVerticalList
    HList = VisualizableHorizontalList

    LevelSize = VisualizableLevelSize
    Page = VisualizablePage
    Level = VisualizableLevel

    @classmethod
    @property
    def python_base_path(cls):
        return PythonModuleBasePaths.Visualizer.value

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

    def before_run(self):
        super().before_run()
        logger.info(f"STARTED visualizer: {self.__repr__()}")

    def after_run_success(self, content):
        if not isinstance(content, list):
            raise VisualizerRunException(
                f"Report has not correct type: {type(self.report.report)}"
            )
        for elem in content:
            if not isinstance(elem, tuple) or not isinstance(elem[1], list):
                raise VisualizerRunException(
                    f"Report Page has not correct type: {type(elem)}"
                )
        super().after_run_success(content)
        for i, page in enumerate(content):
            if i == 0:
                report = self.report
            else:
                report = self.copy_report()
            name, content = page
            report.name = name
            report.report = content
            report.save()

    def after_run(self):
        super().after_run()
        logger.info(f"FINISHED visualizer: {self.__repr__()}")

    def copy_report(self) -> VisualizerReport:
        report = self.report
        report.pk = None
        report.save()
        return report

    def analyzer_reports(self) -> QuerySet:
        from api_app.analyzers_manager.models import AnalyzerReport

        return AnalyzerReport.objects.filter(job=self._job)

    def connector_reports(self) -> QuerySet:
        from api_app.connectors_manager.models import ConnectorReport

        return ConnectorReport.objects.filter(job=self._job)

    def pivots_reports(self) -> QuerySet:
        from api_app.pivots_manager.models import PivotReport

        return PivotReport.objects.filter(job=self._job)
