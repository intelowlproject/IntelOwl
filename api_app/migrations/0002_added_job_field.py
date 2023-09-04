# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import django.contrib.postgres.fields.jsonb as jsonb
from django.db import migrations


class Migration(migrations.Migration):
    initial = True

    dependencies = [("api_app", "0001_initial")]

    operations = [
        migrations.AddField(
            model_name="job",
            name="runtime_configuration",
            field=jsonb.JSONField(default=dict, null=False, blank=True),
        )
    ]
