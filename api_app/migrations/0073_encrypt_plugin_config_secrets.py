# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import base64
import hashlib
import json

from django.conf import settings
from django.db import migrations


def _get_fernet():
    from cryptography.fernet import Fernet

    key = getattr(settings, "PLUGIN_CONFIG_FERNET_KEY", None)
    if key is None:
        key = base64.urlsafe_b64encode(
            hashlib.sha256(settings.SECRET_KEY.encode()).digest()
        )
    return Fernet(key)


def encrypt_existing_secrets(apps, schema_editor):
    PluginConfig = apps.get_model("api_app", "PluginConfig")
    fernet = _get_fernet()

    for pc in PluginConfig.objects.filter(
        parameter__is_secret=True,
        value__isnull=False,
    ):
        if isinstance(pc.value, str) and pc.value.startswith("gAAAAA"):
            continue
        encrypted = fernet.encrypt(json.dumps(pc.value).encode()).decode()
        PluginConfig.objects.filter(pk=pc.pk).update(value=encrypted)


def decrypt_existing_secrets(apps, schema_editor):
    PluginConfig = apps.get_model("api_app", "PluginConfig")
    fernet = _get_fernet()

    for pc in PluginConfig.objects.filter(
        parameter__is_secret=True,
        value__isnull=False,
    ):
        if not (isinstance(pc.value, str) and pc.value.startswith("gAAAAA")):
            continue
        try:
            decrypted = json.loads(fernet.decrypt(pc.value.encode()).decode())
            PluginConfig.objects.filter(pk=pc.pk).update(value=decrypted)
        except Exception:
            pass


class Migration(migrations.Migration):

    dependencies = [
        ("api_app", "0072_update_check_system"),
    ]

    operations = [
        migrations.RunPython(
            encrypt_existing_secrets,
            reverse_code=decrypt_existing_secrets,
        ),
    ]
