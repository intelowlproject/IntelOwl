# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
from django.db import models

from api_app.analyzers_manager.constants import AllTypes
from api_app.analyzers_manager.models import AnalyzerConfig
from api_app.connectors_manager.models import ConnectorConfig
from api_app.fields import ChoiceArrayField
from api_app.validators import validate_runtime_configuration_playbook


class PlaybookConfig(models.Model):
    name = models.CharField(max_length=30, null=False, unique=True, primary_key=True)
    type = ChoiceArrayField(
        models.CharField(choices=AllTypes.choices, null=False, max_length=50)
    )
    description = models.TextField(null=False)
    disabled = models.BooleanField(null=False, default=False)

    analyzers = models.ManyToManyField(
        AnalyzerConfig, related_name="playbooks", blank=True
    )
    connectors = models.ManyToManyField(
        ConnectorConfig, related_name="playbooks", blank=True
    )

    runtime_configuration = models.JSONField(
        blank=True,
        default=dict,
        null=False,
        validators=[validate_runtime_configuration_playbook],
    )
