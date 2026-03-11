# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("data_model_manager", "0011_data_model_date_index"),
    ]

    operations = [
        migrations.AddField(
            model_name="domaindatamodel",
            name="content_hash",
            field=models.CharField(
                blank=True,
                db_index=True,
                help_text="Hash of normalized content for deduplication of identical data models.",
                max_length=64,
                null=True,
                unique=True,
            ),
        ),
        migrations.AddField(
            model_name="filedatamodel",
            name="content_hash",
            field=models.CharField(
                blank=True,
                db_index=True,
                help_text="Hash of normalized content for deduplication of identical data models.",
                max_length=64,
                null=True,
                unique=True,
            ),
        ),
        migrations.AddField(
            model_name="ipdatamodel",
            name="content_hash",
            field=models.CharField(
                blank=True,
                db_index=True,
                help_text="Hash of normalized content for deduplication of identical data models.",
                max_length=64,
                null=True,
                unique=True,
            ),
        ),
    ]
