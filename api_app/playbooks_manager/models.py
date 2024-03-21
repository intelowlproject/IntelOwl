# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
import datetime

from django.core.exceptions import ValidationError
from django.db import models

from api_app.analyzers_manager.constants import AllTypes
from api_app.choices import TLP, ScanMode
from api_app.defaults import default_runtime
from api_app.fields import ChoiceArrayField
from api_app.interfaces import OwnershipAbstractModel
from api_app.models import AbstractConfig, Tag
from api_app.playbooks_manager.queryset import PlaybookConfigQuerySet
from api_app.validators import validate_runtime_configuration


class PlaybookConfig(AbstractConfig, OwnershipAbstractModel):
    objects = PlaybookConfigQuerySet.as_manager()
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
    scan_mode = models.IntegerField(
        choices=ScanMode.choices,
        null=False,
        blank=False,
        default=ScanMode.CHECK_PREVIOUS_ANALYSIS.value,
    )
    scan_check_time = models.DurationField(
        null=True, blank=True, default=datetime.timedelta(hours=24)
    )

    tags = models.ManyToManyField(Tag, related_name="playbooks", blank=True)

    tlp = models.CharField(max_length=8, choices=TLP.choices)

    class Meta:
        ordering = ["name", "disabled"]
        indexes = OwnershipAbstractModel.Meta.indexes
        unique_together = [["name", "owner"]]

    def _generate_tlp(self) -> str:
        tlps = [
            TLP[x]
            for x in list(self.analyzers.values_list("maximum_tlp", flat=True))
            + list(self.connectors.values_list("maximum_tlp", flat=True))
        ]
        # analyzer -> amber
        # playbook -> green  => analyzer it is executed
        # --------------
        # analyzer -> amber
        # playbook -> red => analyzer it is not executed
        # ========> the playbook tlp is the minimum of all tlp of all plugins
        return min(tlps, default=TLP.CLEAR).value

    def clean_scan(self):
        if (
            self.scan_mode == ScanMode.FORCE_NEW_ANALYSIS.value
            and self.scan_check_time is not None
        ):
            raise ValidationError(
                f"You can't have set mode to {ScanMode.FORCE_NEW_ANALYSIS.name}"
                " and have check_time set"
            )
        elif (
            self.scan_mode == ScanMode.CHECK_PREVIOUS_ANALYSIS.value
            and self.scan_check_time is None
        ):
            raise ValidationError(
                f"You can't have set mode to {ScanMode.CHECK_PREVIOUS_ANALYSIS.name}"
                " and not have check_time set"
            )

    def clean(self) -> None:
        super().clean()
        self.clean_scan()

    def is_sample(self) -> bool:
        return AllTypes.FILE.value in self.type
