from django.conf import settings
from django.db import migrations


class Migration(migrations.Migration):
    """
    two_factor used to contain the PhoneDevice model, now moved to a plugin
    directory. This squashed migration avoid for new projects to run those
    old migration files requiring phonenumber_field imports (now optional).
    """

    replaces = [
        ("two_factor", "0001_initial"),
        ("two_factor", "0002_auto_20150110_0810"),
        ("two_factor", "0003_auto_20150817_1733"),
        ("two_factor", "0004_auto_20160205_1827"),
        ("two_factor", "0005_auto_20160224_0450"),
        ("two_factor", "0006_phonedevice_key_default"),
        ("two_factor", "0007_auto_20201201_1019"),
        ("two_factor", "0008_delete_phonedevice"),
    ]

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = []
