# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import typing

from django.db import models


class Position(models.TextChoices):
    LEFT = "left"
    CENTER = "center"
    RIGHT = "right"


class TLP(models.TextChoices):
    WHITE = "WHITE"
    GREEN = "GREEN"
    AMBER = "AMBER"
    RED = "RED"

    @classmethod
    def get_priority(cls, tlp):
        order = {
            cls.WHITE: 0,
            cls.GREEN: 1,
            cls.AMBER: 2,
            cls.RED: 3,
        }
        return order[tlp]


class Status(models.TextChoices):
    PENDING = "pending", "pending"
    RUNNING = "running", "running"
    REPORTED_WITHOUT_FAILS = "reported_without_fails", "reported_without_fails"
    REPORTED_WITH_FAILS = "reported_with_fails", "reported_with_fails"
    KILLED = "killed", "killed"
    FAILED = "failed", "failed"

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
