import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):
    initial = True
    replaces = [
        # ("pivots_manager", "0001_initial"),
        # (
        #     "pivots_manager",
        #     "0002_rename_pivot_manag_startin_21e74a_idx_pivots_mana_startin_694120_idx_and_more",
        # ),
        # ("pivots_manager", "0003_alter_pivot_ending_job_alter_pivot_starting_job"),
        # ("pivots_manager", "0004_alter_pivotconfig_analyzer_config_and_more"),
        # ("pivots_manager", "0005_pivotconfig_pivot_config_no_config_all_null"),
        # ("pivots_manager", "0006_alter_pivotconfig_analyzer_config_and_more"),
        # ("pivots_manager", "0007_pivotreport_rename_pivot_pivotmap_and_more"),
        # ("pivots_manager", "0008_data_migrate"),
        # ("pivots_manager", "0009_alter_pivotconfig_python_module"),
        # ("pivots_manager", "0010_alter_pivotconfig_execute_on_python_module"),
        # ("pivots_manager", "0011_alter_pivotconfig_name"),
        # ("pivots_manager", "0012_alter_pivotconfig_unique_together_and_more"),
        # ("pivots_manager", "0013_pivotconfig_pivot_config_no_null_configs"),
        # ("pivots_manager", "0014_pivotconfig_no_field_to_compare"),
        # ("pivots_manager", "0015_alter_pivotmap_pivot_config"),
        # ("pivots_manager", "0016_alter_pivotconfig_options_and_more"),
        # ("pivots_manager", "0017_pivotconfig_routing_key_pivotconfig_soft_time_limit"),
        # ("pivots_manager", "0018_pivotconfig_health_check_task"),
        # ("pivots_manager", "0019_pivotconfig_health_check_status"),
        # ("pivots_manager", "0020_pivotreport_parameters"),
        # ("pivots_manager", "0021_pivotreport_sent_to_bi"),
        # ("pivots_manager", "0022_pivotreport_pivotreportsbisearch"),
    ]
    dependencies = [
        ("pivots_manager", "0001_1_initial_squashed"),
        ("playbooks_manager", "0001_initial_squashed"),
    ]
    operations = [
        migrations.AddField(
            model_name="pivotconfig",
            name="playbook_to_execute",
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.PROTECT,
                related_name="executed_by_pivot",
                to="playbooks_manager.playbookconfig",
            ),
        )
    ]
