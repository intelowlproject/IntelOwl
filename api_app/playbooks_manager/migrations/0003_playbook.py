# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

# Generated by Django 3.2.18 on 2023-02-22 13:53

from django.db import migrations, models

import api_app.defaults
import api_app.fields
import api_app.models
import api_app.validators


class Migration(migrations.Migration):
    dependencies = [
        ("analyzers_manager", "0003_analyzerconfig"),
        ("connectors_manager", "0003_connectorconfig"),
        ("playbooks_manager", "0002_alter_cachedplaybook_job"),
    ]

    operations = [
        migrations.CreateModel(
            name="PlaybookConfig",
            fields=[
                (
                    "name",
                    models.CharField(
                        max_length=30, primary_key=True, serialize=False, unique=True
                    ),
                ),
                (
                    "type",
                    api_app.fields.ChoiceArrayField(
                        base_field=models.CharField(
                            choices=[
                                ("ip", "Ip"),
                                ("url", "Url"),
                                ("domain", "Domain"),
                                ("hash", "Hash"),
                                ("generic", "Generic"),
                                ("file", "File"),
                            ],
                            max_length=50,
                        ),
                        size=None,
                    ),
                ),
                ("description", models.TextField()),
                ("disabled", models.BooleanField(default=False)),
                (
                    "runtime_configuration",
                    models.JSONField(
                        blank=True,
                        default=api_app.defaults.default_runtime,
                        validators=[api_app.validators.validate_runtime_configuration],
                    ),
                ),
                (
                    "analyzers",
                    models.ManyToManyField(
                        related_name="playbooks",
                        to="analyzers_manager.AnalyzerConfig",
                        blank=True,
                    ),
                ),
                (
                    "connectors",
                    models.ManyToManyField(
                        related_name="playbooks",
                        to="connectors_manager.ConnectorConfig",
                        blank=True,
                    ),
                ),
            ],
        ),
        migrations.DeleteModel(
            name="CachedPlaybook",
        ),
    ]