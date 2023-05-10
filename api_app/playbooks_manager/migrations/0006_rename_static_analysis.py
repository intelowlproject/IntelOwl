# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.db import migrations


def migrate(apps, schema_editor):
    PlaybookConfig = apps.get_model("playbooks_manager", "PlaybookConfig")
    pc = PlaybookConfig.objects.get(name="Sample Static Analsis")
    pc.name = "Sample Static Analysis"
    pc.save()
    PlaybookConfig.objects.get(name="Sample Static Analsis").delete()


def reverse_migrate(apps, schema_editor):
    PlaybookConfig = apps.get_model("playbooks_manager", "PlaybookConfig")
    pc = PlaybookConfig.objects.get(name="Sample Static Analysis")
    pc.name = "Sample Static Analsis"
    pc.save()
    PlaybookConfig.objects.get(name="Sample Static Analysis").delete()



class Migration(migrations.Migration):

    dependencies = [
        ('playbooks_manager', '0005_static_analysis'),
    ]

    operations = [
        migrations.RunPython(
            migrate, reverse_migrate
        ),
    ]
