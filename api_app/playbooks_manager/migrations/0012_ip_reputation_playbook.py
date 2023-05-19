# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.db import migrations
from django.db.models.fields.related_descriptors import ManyToManyDescriptor

objects = [
    {
        "model": "playbooks_manager.playbookconfig",
        "pk": "Popular_IP_Reputation_Services",
        "fields": {
            "type": '["ip"]',
            "description": "Collection of the most popular"
            " and free reputation analyzers for IP addresses",
            "disabled": False,
            "runtime_configuration": {
                "analyzers": {},
                "connectors": {},
                "visualizers": {},
            },
            "analyzers": [
                "AbuseIPDB",
                "TorProject",
                "URLhaus",
                "VirusTotal_v3_Get_Observable",
                "FireHol_IPList",
                "InQuest_REPdb",
                "TalosReputation",
                "GreedyBear",
                "ThreatFox",
                "Crowdsec",
                "GreyNoiseCommunity",
                "OTXQuery",
            ],
            "connectors": [],
        },
    }
]


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
        ("playbooks_manager", "0011_fix_static_analysis"),
    ]

    operations = [
        migrations.RunPython(migrate, reverse_migrate),
    ]
