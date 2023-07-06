# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
from django.db import models

from api_app.analyzers_manager.constants import AllTypes
from api_app.core.models import AbstractConfig
from api_app.fields import ChoiceArrayField
from api_app.models import default_runtime
from api_app.playbooks_manager.queryset import PlaybookConfigQuerySet
from api_app.validators import plugin_name_validator, validate_runtime_configuration


class PlaybookConfig(AbstractConfig):
    objects = PlaybookConfigQuerySet.as_manager()
    name = models.CharField(
        max_length=100,
        null=False,
        unique=True,
        primary_key=True,
        validators=[plugin_name_validator],
    )
    type = ChoiceArrayField(
        models.CharField(choices=AllTypes.choices, null=False, max_length=50)
    )

    analyzers = models.ManyToManyField(
        "analyzers_manager.AnalyzerConfig", related_name="playbooks", blank=True
    )
    connectors = models.ManyToManyField(
        "connectors_manager.ConnectorConfig", related_name="playbooks", blank=True
    )
    pivots = models.ManyToManyField(
        "pivots_manager.PivotConfig", related_name="used_by_playbooks", blank=True
    )
    runtime_configuration = models.JSONField(
        blank=True,
        default=default_runtime,
        null=False,
        validators=[validate_runtime_configuration],
    )

    class Meta:
        ordering = ["name", "disabled"]
