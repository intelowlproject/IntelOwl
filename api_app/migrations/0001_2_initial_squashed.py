import django.db.migrations.operations.special
import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):
    initial = True
    dependencies = [
        ("api_app", "0001_1_initial_squashed"),
        ("analyzers_manager", "0001_initial_squashed"),
        ("connectors_manager", "0001_initial_squashed"),
        ("visualizers_manager", "0001_initial_squashed"),
        ("playbooks_manager", "0001_initial_squashed"),
        ("ingestors_manager", "0001_initial_squashed"),
        ("pivots_manager", "0001_1_initial_squashed"),
    ]
    operations = [
        migrations.CreateModel(
            name="PluginConfig",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("value", models.JSONField(blank=True, null=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "owner",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="custom_configs",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
                (
                    "parameter",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="values",
                        to="api_app.parameter",
                    ),
                ),
                ("for_organization", models.BooleanField(default=False)),
                (
                    "pivot_config",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="values",
                        to="pivots_manager.pivotconfig",
                    ),
                ),
                (
                    "visualizer_config",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="values",
                        to="visualizers_manager.visualizerconfig",
                    ),
                ),
                (
                    "ingestor_config",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="values",
                        to="ingestors_manager.ingestorconfig",
                    ),
                ),
                (
                    "connector_config",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="values",
                        to="connectors_manager.connectorconfig",
                    ),
                ),
                (
                    "analyzer_config",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="values",
                        to="analyzers_manager.analyzerconfig",
                    ),
                ),
            ],
        ),
        migrations.AddIndex(
            model_name="pluginconfig",
            index=models.Index(
                fields=["owner", "for_organization", "parameter"],
                name="api_app_plu_owner_i_55ca9b_idx",
            ),
        ),
        migrations.AddIndex(
            model_name="pluginconfig",
            index=models.Index(
                fields=["owner", "for_organization"],
                name="api_app_plu_owner_i_c6658a_idx",
            ),
        ),
        migrations.AlterUniqueTogether(
            name="pluginconfig",
            unique_together=set(),
        ),
        migrations.AddConstraint(
            model_name="pluginconfig",
            constraint=models.UniqueConstraint(
                condition=models.Q(("owner__isnull", False)),
                fields=("owner", "for_organization", "parameter", "analyzer_config"),
                name="plugin_config_unique_with_analyzer_config_owner",
            ),
        ),
        migrations.AddConstraint(
            model_name="pluginconfig",
            constraint=models.UniqueConstraint(
                condition=models.Q(("owner__isnull", True)),
                fields=("for_organization", "parameter", "analyzer_config"),
                name="plugin_config_unique_with_analyzer_config",
            ),
        ),
        migrations.AddConstraint(
            model_name="pluginconfig",
            constraint=models.UniqueConstraint(
                condition=models.Q(("owner__isnull", False)),
                fields=("owner", "for_organization", "parameter", "connector_config"),
                name="plugin_config_unique_with_connector_config_owner",
            ),
        ),
        migrations.AddConstraint(
            model_name="pluginconfig",
            constraint=models.UniqueConstraint(
                condition=models.Q(("owner__isnull", True)),
                fields=("for_organization", "parameter", "connector_config"),
                name="plugin_config_unique_with_connector_config",
            ),
        ),
        migrations.AddConstraint(
            model_name="pluginconfig",
            constraint=models.UniqueConstraint(
                condition=models.Q(("owner__isnull", False)),
                fields=("owner", "for_organization", "parameter", "visualizer_config"),
                name="plugin_config_unique_with_visualizer_config_owner",
            ),
        ),
        migrations.AddConstraint(
            model_name="pluginconfig",
            constraint=models.UniqueConstraint(
                condition=models.Q(("owner__isnull", True)),
                fields=("for_organization", "parameter", "visualizer_config"),
                name="plugin_config_unique_with_visualizer_config",
            ),
        ),
        migrations.AddConstraint(
            model_name="pluginconfig",
            constraint=models.UniqueConstraint(
                condition=models.Q(("owner__isnull", False)),
                fields=("owner", "for_organization", "parameter", "ingestor_config"),
                name="plugin_config_unique_with_ingestor_config_owner",
            ),
        ),
        migrations.AddConstraint(
            model_name="pluginconfig",
            constraint=models.UniqueConstraint(
                condition=models.Q(("owner__isnull", True)),
                fields=("for_organization", "parameter", "ingestor_config"),
                name="plugin_config_unique_with_ingestor_config",
            ),
        ),
        migrations.AddConstraint(
            model_name="pluginconfig",
            constraint=models.CheckConstraint(
                check=models.Q(
                    ("analyzer_config__isnull", True),
                    ("connector_config__isnull", True),
                    ("visualizer_config__isnull", True),
                    ("ingestor_config__isnull", True),
                    ("pivot_config__isnull", True),
                    _connector="OR",
                ),
                name="plugin_config_no_config_all_null",
            ),
        ),
        migrations.AddConstraint(
            model_name="pluginconfig",
            constraint=models.UniqueConstraint(
                condition=models.Q(("owner__isnull", False)),
                fields=("owner", "for_organization", "parameter", "pivot_config"),
                name="plugin_config_unique_with_pivot_config_owner",
            ),
        ),
        migrations.AddConstraint(
            model_name="pluginconfig",
            constraint=models.UniqueConstraint(
                condition=models.Q(("owner__isnull", True)),
                fields=("for_organization", "parameter", "pivot_config"),
                name="plugin_config_unique_with_pivot_config",
            ),
        ),
        migrations.AddField(
            model_name="job",
            name="analyzers_requested",
            field=models.ManyToManyField(
                blank=True,
                related_name="requested_in_jobs",
                to="analyzers_manager.analyzerconfig",
            ),
        ),
        migrations.AddField(
            model_name="job",
            name="analyzers_to_execute",
            field=models.ManyToManyField(
                blank=True,
                related_name="executed_in_jobs",
                to="analyzers_manager.analyzerconfig",
            ),
        ),
        migrations.AddField(
            model_name="job",
            name="connectors_requested",
            field=models.ManyToManyField(
                blank=True,
                related_name="requested_in_jobs",
                to="connectors_manager.connectorconfig",
            ),
        ),
        migrations.AddField(
            model_name="job",
            name="connectors_to_execute",
            field=models.ManyToManyField(
                blank=True,
                related_name="executed_in_jobs",
                to="connectors_manager.connectorconfig",
            ),
        ),
        migrations.AddField(
            model_name="job",
            name="playbook_requested",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="requested_in_jobs",
                to="playbooks_manager.playbookconfig",
            ),
        ),
        migrations.AddField(
            model_name="job",
            name="playbook_to_execute",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="executed_in_jobs",
                to="playbooks_manager.playbookconfig",
            ),
        ),
        migrations.AddField(
            model_name="job",
            name="visualizers_to_execute",
            field=models.ManyToManyField(
                blank=True,
                related_name="executed_in_jobs",
                to="visualizers_manager.visualizerconfig",
            ),
        ),
        migrations.AddIndex(
            model_name="job",
            index=models.Index(
                fields=["playbook_to_execute", "finished_analysis_time", "user"],
                name="PlaybookConfigOrdering",
            ),
        ),
        migrations.AlterField(
            model_name="pythonmodule",
            name="base_path",
            field=models.CharField(
                choices=[
                    (
                        "api_app.analyzers_manager.observable_analyzers",
                        "Observable Analyzer",
                    ),
                    (
                        "api_app.analyzers_manager.file_analyzers",
                        "File Analyzer",
                    ),
                    ("api_app.connectors_manager.connectors", "Connector"),
                    ("api_app.ingestors_manager.ingestors", "Ingestor"),
                    ("api_app.visualizers_manager.visualizers", "Visualizer"),
                    ("api_app.pivots_manager.pivots", "Pivot"),
                ],
                db_index=True,
                max_length=120,
            ),
        ),
        migrations.AlterField(
            model_name="pluginconfig",
            name="owner",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.CASCADE,
                related_name="+",
                to=settings.AUTH_USER_MODEL,
            ),
        ),
    ]
