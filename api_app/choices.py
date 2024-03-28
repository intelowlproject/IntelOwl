# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
import enum
import typing
from pathlib import PosixPath

import _operator
from django.db import models


class PythonModuleBasePaths(models.TextChoices):
    ObservableAnalyzer = (
        PosixPath("api_app.analyzers_manager.observable_analyzers"),
        "Observable Analyzer",
    )
    FileAnalyzer = (
        PosixPath("api_app.analyzers_manager.file_analyzers"),
        "File Analyzer",
    )
    Connector = PosixPath("api_app.connectors_manager.connectors"), "Connector"
    Ingestor = PosixPath("api_app.ingestors_manager.ingestors"), "Ingestor"
    Visualizer = PosixPath("api_app.visualizers_manager.visualizers"), "Visualizer"
    Pivot = PosixPath("api_app.pivots_manager.pivots"), "Pivot"


class TLP(models.TextChoices):
    CLEAR = "CLEAR"
    GREEN = "GREEN"
    AMBER = "AMBER"
    RED = "RED"

    @classmethod
    def get_priority(cls, tlp):
        order = {
            cls.CLEAR: 0,
            cls.GREEN: 1,
            cls.AMBER: 2,
            cls.RED: 3,
        }
        return order[tlp]

    def __compare(self, other, operator):
        if not isinstance(other, TLP):
            raise TypeError(f"Can sum {self.__class__.__name__} with {type(other)}")

        return operator(self.get_priority(self), self.get_priority(other))

    def __gt__(self, other):
        return self.__compare(other, _operator.gt)

    def __lt__(self, other):
        return self.__compare(other, _operator.lt)


class Status(models.TextChoices):
    PENDING = "pending", "pending"
    RUNNING = "running", "running"

    ANALYZERS_RUNNING = "analyzers_running", "analyzers_running"
    ANALYZERS_COMPLETED = "analyzers_completed", "analyzers_completed"

    CONNECTORS_RUNNING = "connectors_running", "connectors_running"
    CONNECTORS_COMPLETED = "connectors_completed", "connectors_completed"

    PIVOTS_RUNNING = "pivots_running", "pivots_running"
    PIVOTS_COMPLETED = "pivots_completed", "pivots_completed"

    VISUALIZERS_RUNNING = "visualizers_running", "visualizers_running"
    VISUALIZERS_COMPLETED = "visualizers_completed", "visualizers_completed"

    REPORTED_WITHOUT_FAILS = "reported_without_fails", "reported_without_fails"
    REPORTED_WITH_FAILS = "reported_with_fails", "reported_with_fails"
    KILLED = "killed", "killed"
    FAILED = "failed", "failed"

    @classmethod
    def get_enums_with_suffix(
        cls, suffix: str
    ) -> typing.Generator[enum.Enum, None, None]:
        for key in cls:
            if key.name.endswith(suffix):
                yield key

    @classmethod
    def running_statuses(cls) -> typing.List["Status"]:
        return list(cls.get_enums_with_suffix("_RUNNING"))

    @classmethod
    def partial_statuses(cls) -> typing.List["Status"]:
        return list(cls.get_enums_with_suffix("_COMPLETED"))

    @classmethod
    def final_statuses(cls) -> typing.List["Status"]:
        return [
            cls.REPORTED_WITHOUT_FAILS,
            cls.REPORTED_WITH_FAILS,
            cls.KILLED,
            cls.FAILED,
        ]


class ObservableClassification(models.TextChoices):
    IP = "ip"
    URL = "url"
    DOMAIN = "domain"
    HASH = "hash"
    GENERIC = "generic"
    EMPTY = ""


class ScanMode(models.IntegerChoices):
    FORCE_NEW_ANALYSIS = 1
    CHECK_PREVIOUS_ANALYSIS = 2


class ReportStatus(models.TextChoices):
    FAILED = "FAILED"
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    SUCCESS = "SUCCESS"
    KILLED = "KILLED"

    @classmethod
    def final_statuses(cls):
        return [cls.FAILED, cls.SUCCESS, cls.KILLED]


class ParamTypes(models.TextChoices):
    INT = "int"
    FLOAT = "float"
    STR = "str"
    BOOL = "bool"
    LIST = "list"
    DICT = "dict"
