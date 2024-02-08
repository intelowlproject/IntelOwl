import django.contrib.postgres.fields
import django.contrib.postgres.fields.jsonb
import django.core.validators
import django.db.migrations.operations.special
import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):
    replaces = [
        #             ('api_app', '0003_auto_20201020_1406'), ('api_app', '0004_auto_20201112_0021'),
        #             ('api_app', '0005_auto_20210610_1028'), ('api_app', '0006_v3_release'),
        #             ('api_app', '0007_alter_tag_color'), ('api_app', '0008_job_user_field'),
        #             ('api_app', '0009_datamigration'), ('api_app', '0010_custom_config_playbooks'),
        #             ('api_app', '0011_alter_organizationpluginstate_organization'), ('api_app', '0012_auto_20221227_1543'),
        #             ('api_app', '0013_alter_job_observable_classification'), ('api_app', '0014_add_job_process_time'),
        #             ('api_app', '0015_visualizer'), ('api_app', '0016_add_index'),
        #             ('api_app', '0017_delete_organizationpluginstate'), ('api_app', '0018_tag_validation'),
        #             ('api_app', '0019_mitm_configs'), ('api_app', '0020_single_playbook_pre_migration'),
        #             ('api_app', '0021_single_playbook_migration'), ('api_app', '0022_single_playbook_post_migration'),
        #             ('api_app', '0023_runtime_config'), ('api_app', '0024_tlp'), ('api_app', '0025_comment'),
        #             ('api_app', '0026_pluginconfig_api_app_plu_organiz_0867bd_idx'), ('api_app', '0027_parameter'),
        #             ('api_app', '0028_plugin_config'),
        #             ('api_app', '0029_parameter_api_app_par_analyze_1f1bee_idx_and_more'),
        #             ('api_app', '0030_pluginconfig_repositories'), ('api_app', '0031_job_playbookconfigordering'),
        #             ('api_app', '0032_alter_job_status'), ('api_app', '0033_alter_parameter_unique_together'),
        #             ('api_app', '0034_job_scan_check_time_job_scan_mode'), ('api_app', '0035_pluginconfig_repositories'),
        #             ('api_app', '0036_alter_parameter_unique_together_and_more'), ('api_app', '0037_pythonmodule_and_more'),
        # ("api_app", "0038_python_module_datamigration"),
        # ("api_app", "0039_remove_fields"),
        # ("api_app", "0040_alter_pythonmodule_base_path"),
        # ("api_app", "0041_alter_pythonmodule_unique_together"),
        # ("api_app", "0042_alter_pluginconfig_unique_together_and_more"),
        # ("api_app", "0043_pluginconfig_plugin_config_no_config_all_null"),
        # ("api_app", "0044_alter_pluginconfig_analyzer_config_and_more"),
        # ("api_app", "0045_remove_pluginconfig_unique_with_analyzer_config_and_more"),
        # (
        #     "api_app",
        #     "0046_remove_pluginconfig_plugin_config_no_config_all_null_and_more",
        # ),
        # ("api_app", "0047_alter_pythonmodule_options"),
        # ("api_app", "0048_job_warnings"),
        # ("api_app", "0049_remove_pluginconfig_api_app_plu_owner_i_691c79_idx_and_more"),
        # ("api_app", "0050_python_module_update_task"),
        # ("api_app", "0051_pythonmodule_health_check_schedule_and_more"),
        # ("api_app", "0052_periodic_task_bi"),
        # ("api_app", "0053_job_sent_to_bi"),
        # ("api_app", "0054_job_jobbisearch"),
    ]
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
    ]
