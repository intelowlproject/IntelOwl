# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import typing

from django.db import models


class Position(models.TextChoices):
    LEFT = "left"
    CENTER = "center"
    RIGHT = "right"


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


class Status(models.TextChoices):
    PENDING = "pending", "pending"
    RUNNING = "running", "running"

    ANALYZERS_RUNNING = "analyzers_running", "analyzers_running"
    CONNECTORS_RUNNING = "connectors_running", "connectors_running"
    VISUALIZERS_RUNNING = "visualizers_running", "visualizers_running"

    ANALYZERS_COMPLETED = "analyzers_completed", "analyzers_completed"
    CONNECTORS_COMPLETED = "connectors_completed", "connectors_completed"
    VISUALIZERS_COMPLETED = "visualizers_completed", "visualizers_completed"

    REPORTED_WITHOUT_FAILS = "reported_without_fails", "reported_without_fails"
    REPORTED_WITH_FAILS = "reported_with_fails", "reported_with_fails"
    KILLED = "killed", "killed"
    FAILED = "failed", "failed"

    @classmethod
    def running_statuses(cls) -> typing.List["Status"]:
        return [
            cls.ANALYZERS_RUNNING,
            cls.CONNECTORS_RUNNING,
            cls.VISUALIZERS_RUNNING,
        ]

    @classmethod
    def partial_statuses(cls) -> typing.List["Status"]:
        return [
            cls.ANALYZERS_COMPLETED,
            cls.CONNECTORS_COMPLETED,
            cls.VISUALIZERS_COMPLETED,
        ]

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
