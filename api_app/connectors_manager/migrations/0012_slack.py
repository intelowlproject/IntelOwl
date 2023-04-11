# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.db import migrations
from django.db.models.fields.related_descriptors import ManyToManyDescriptor

objects = [{"model": "connectors_manager.connectorconfig",
            "pk": "Slack", "fields": {"python_module": "slack.Slack",
"description": "Send the analysis link to a slack channel", "disabled": False, "config": {"queue": "default", "soft_time_limit": 60}, "secrets": {"token": {"type": "str", "required": True, "description": "Slack token for authentication"}, "channel": {"type": "str", "required": True, "description": "Slack channel to send messages"}}, "params": {"slack_username": {"type": "str", "default": None, "description": "Slack username to tag on the message"}}, "maximum_tlp": "RED", "run_on_failure": True, "disabled_in_organizations": []}}]


def migrate(apps, schema_editor):
    for obj in objects:
        python_path = obj["model"]
        Model = apps.get_model(*python_path.split("."))
        no_mtm = {}
        mtm = {}
        for field, value in obj["fields"].items():
            if type(getattr(Model, field)) != ManyToManyDescriptor:
                no_mtm[field] = value
            else:
                mtm[field] = value
        o = Model(**no_mtm, pk=obj["pk"])
        o.full_clean()
        o.save()
        for field, value in mtm.items():
            attribute = getattr(o, field)
            attribute.set(value)


def reverse_migrate(apps, schema_editor):
    for obj in objects:
        python_path = obj["model"]
        Model = apps.get_model(*python_path.split("."))
        Model.objects.get(pk=obj["pk"]).delete()


class Migration(migrations.Migration):

    dependencies = [
        ('connectors_manager', '00011_remove_runtime_configuration'),
    ]

    operations = [
        migrations.RunPython(
            migrate, reverse_migrate
        ),
    ]
