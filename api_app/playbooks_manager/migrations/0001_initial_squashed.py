# Generated by Django 4.2.8 on 2024-02-08 13:40

import datetime

import django.core.validators
import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models

import api_app.defaults
import api_app.fields
import api_app.validators


class Migration(migrations.Migration):
    initial = True

    dependencies = [
        ("api_app", "0001_1_initial_squashed"),
        ("analyzers_manager", "0001_initial_squashed"),
        ("connectors_manager", "0001_initial_squashed"),
        ("pivots_manager", "0001_1_initial_squashed"),
    ]

    operations = [
        migrations.CreateModel(
            name="PlaybookConfig",
            fields=[
                (
                    "name",
                    models.CharField(
                        max_length=100,
                        primary_key=True,
                        serialize=False,
                        validators=[
                            django.core.validators.RegexValidator(
                                "^\\w+$",
                                "Your name should match the [A-Za-z0-9_] characters",
                            )
                        ],
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
                        blank=True,
                        related_name="playbooks",
                        to="analyzers_manager.analyzerconfig",
                    ),
                ),
                (
                    "connectors",
                    models.ManyToManyField(
                        blank=True,
                        related_name="playbooks",
                        to="connectors_manager.connectorconfig",
                    ),
                ),
                (
                    "owner",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="+",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
                ("for_organization", models.BooleanField(default=False)),
                (
                    "tlp",
                    models.CharField(
                        choices=[
                            ("CLEAR", "Clear"),
                            ("GREEN", "Green"),
                            ("AMBER", "Amber"),
                            ("RED", "Red"),
                        ],
                        max_length=8,
                    ),
                ),
                (
                    "tags",
                    models.ManyToManyField(
                        blank=True, related_name="playbooks", to="api_app.tag"
                    ),
                ),
                (
                    "scan_mode",
                    models.IntegerField(
                        choices=[
                            (1, "Force New Analysis"),
                            (2, "Check Previous Analysis"),
                        ],
                        default=2,
                    ),
                ),
                (
                    "scan_check_time",
                    models.DurationField(
                        blank=True, default=datetime.timedelta(days=1), null=True
                    ),
                ),
                (
                    "pivots",
                    models.ManyToManyField(
                        blank=True,
                        related_name="used_by_playbooks",
                        to="pivots_manager.pivotconfig",
                    ),
                ),
                (
                    "disabled_in_organizations",
                    models.ManyToManyField(
                        blank=True,
                        related_name="%(app_label)s_%(class)s_disabled",
                        to="certego_saas_organization.organization",
                    ),
                ),
            ],
        ),
        migrations.AlterModelOptions(
            name="playbookconfig",
            options={"ordering": ["name", "disabled"]},
        ),
        migrations.AddIndex(
            model_name="playbookconfig",
            index=models.Index(
                fields=["owner", "for_organization"],
                name="playbooks_m_owner_i_88fb49_idx",
            ),
        ),
        migrations.AlterUniqueTogether(
            name="playbookconfig",
            unique_together={("name", "owner")},
        ),
    ]
