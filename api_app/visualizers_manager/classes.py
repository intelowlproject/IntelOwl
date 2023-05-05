# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
import abc
import logging
from enum import Enum
from typing import Any, Dict, List, Tuple, Type, Union

from django.conf import settings
from django.db.models import QuerySet

from api_app.core.classes import Plugin
from api_app.visualizers_manager.enums import (
    VisualizableAlignment,
    VisualizableColor,
    VisualizableIcon,
)
from api_app.visualizers_manager.exceptions import (
    VisualizerConfigurationException,
    VisualizerRunException,
)
from api_app.visualizers_manager.models import VisualizerConfig, VisualizerReport

logger = logging.getLogger(__name__)


class VisualizableObject:
    def __init__(self, disable: bool = True):
        self.disable = disable

    @property
    def attributes(self) -> List[str]:
        return ["disable"]

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
        color: VisualizableColor = VisualizableColor.TRANSPARENT,
        link: str = "",
        # you can use an element of the enum or an iso3166 alpha2 code (for flags)
        icon: Union[VisualizableIcon, str] = VisualizableIcon.EMPTY,
        bold: bool = False,
        italic: bool = False,
        classname: str = "",
        disable: bool = True,
    ):
        super().__init__(disable)
        self.value = value
        self.color = color
        self.link = link
        self.icon = icon
        self.bold = bold
        self.italic = italic
        self.classname = classname

    @property
    def attributes(self) -> List[str]:
        return super().attributes + [
            "value",
            "color",
            "link",
            "classname",
            "icon",
            "bold",
            "italic",
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
        value: VisualizableBase,
        disable: bool = True,
    ):
        super().__init__(disable)
        self.title = title
        self.value = value
        if self.disable != self.title.disable or self.disable != self.value.disable:
            logger.warning(
                "Each part of the title should be disabled. "
                / f"Forcing all to disable={self.disable}"
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
        name: str,
        value: bool,
        *args,
        color: VisualizableColor = VisualizableColor.DANGER,
        **kwargs,
    ):
        super().__init__(*args, color=color, value=value, **kwargs)
        self.name = name

    def __bool__(self):
        return bool(self.name)

    @property
    def attributes(self) -> List[str]:
        return super().attributes + ["name"]

    @property
    def type(self) -> str:
        return "bool"

    def to_dict(self) -> Dict:
        result = super().to_dict()
        # bool does not support bold because the default is bold
        result.pop("bold", None)
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


class VisualizableVerticalList(VisualizableListMixin, VisualizableObject):
    def __init__(
        self,
        name: VisualizableBase,
        value: List[VisualizableObject],
        open: bool = False,  # noqa
        max_elements_number: int = -1,
        add_count_in_title: bool = True,
        disable: bool = True,
    ):
        super().__init__(
            disable=disable,
        )
        if add_count_in_title:
            name.value += f" ({len(value)})"
        self.value = value
        self.max_elements_number = max_elements_number
        self.name = name
        self.add_count_in_title = add_count_in_title
        self.open = open

    @property
    def attributes(self) -> List[str]:
        return super().attributes + ["name", "open", "value"]

    def __bool__(self):
        return True

    @property
    def more_elements_object(self) -> VisualizableBase:
        return VisualizableBase(value="...", bold=True)

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
        super().__init__(disable=False)
        self.value = value
        self.alignment = alignment

    @property
    def attributes(self) -> List[str]:
        return super().attributes + ["value", "alignment"]

    @property
    def type(self) -> str:
        return "horizontal_list"

    def to_dict(self) -> Dict:
        result = super().to_dict()
        return result


class VisualizablePage:
    def __init__(self, name: str = None):
        self._levels = {}
        self.name = name

    def add_level(self, level: int, horizontal_list: VisualizableHorizontalList):
        self._levels[level] = horizontal_list

    def to_dict(self) -> Tuple[str, List[Dict]]:
        return self.name, [
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
    Alignment = VisualizableAlignment

    Base = VisualizableBase
    Title = VisualizableTitle
    Bool = VisualizableBool
    VList = VisualizableVerticalList
    HList = VisualizableHorizontalList

    Page = VisualizablePage

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
