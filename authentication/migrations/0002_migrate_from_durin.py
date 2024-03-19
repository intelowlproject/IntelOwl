# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.conf import settings
from django.db import migrations


def move_token_from_durin(apps, schema_editor):
    if "durin" in settings.INSTALLED_APPS:
        AuthToken = apps.get_model("durin", "AuthToken")
        Client = apps.get_model("durin", "Client")
        Token = apps.get_model("authtoken", "Token")

        for durin_token in AuthToken.objects.all():
            # export only CLI token (client name PyIntelOwl)
            # only in case user didn't have a rest framework token
            if (
                durin_token.client.name == "PyIntelOwl"
                and not Token.objects.filter(user_id=durin_token.user.id).exists()
            ):
                Token.objects.create(key=durin_token.token, user_id=durin_token.user.pk)

        # delete durin db data
        AuthToken.objects.all().delete()
        Client.objects.all().delete()


class Migration(migrations.Migration):
    dependencies = [
        ("authentication", "0001_initial"),
        ("authtoken", "0003_tokenproxy"),
        ("api_app", "0061_job_depth_analysis"),
    ]

    operations = [
        migrations.RunPython(move_token_from_durin, migrations.RunPython.noop),
    ]
