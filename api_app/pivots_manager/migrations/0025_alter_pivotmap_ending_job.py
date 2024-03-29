# Generated by Django 4.2.8 on 2024-02-01 16:04

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("api_app", "0058_4_change_primary_key"),
        ("pivots_manager", "0024_4_change_primary_key"),
    ]

    operations = [
        migrations.AlterField(
            model_name="pivotmap",
            name="ending_job",
            field=models.OneToOneField(
                editable=False,
                on_delete=django.db.models.deletion.CASCADE,
                related_name="pivot_parent",
                to="api_app.job",
            ),
        ),
    ]
