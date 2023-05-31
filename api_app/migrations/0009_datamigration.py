# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.conf import settings
from django.db import migrations


def create_apiaccess_client_for_durin(apps, schema_editor):
    # We can't import the Client model here directly
    Client = apps.get_model("durin", "Client")
    # create APIAccess client
    _ = Client.objects.get_or_create(
        name=settings.REST_DURIN["API_ACCESS_CLIENT_NAME"],
        token_ttl=settings.REST_DURIN["API_ACCESS_CLIENT_TOKEN_TTL"],
    )


class Migration(migrations.Migration):

    dependencies = [
        ("api_app", "0008_job_user_field"),
        ("durin", "0002_client_throttlerate"),  # important
    ]

    operations = [
        migrations.RunPython(
            create_apiaccess_client_for_durin, migrations.RunPython.noop
        ),
    ]
