# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.db import migrations
from django.db.models.fields.related_descriptors import ManyToManyDescriptor

objects = [
    {
        "model": "playbooks_manager.playbookconfig",
        "pk": "Popular_URL_Reputation_Services",
        "fields": {
            "type": '["url", "domain"]',
            "description": "Collection of the most popular"
            " and free reputation analyzers for URLs and Domains",
            "disabled": False,
            "runtime_configuration": {
                "analyzers": {},
                "connectors": {},
                "visualizers": {},
            },
            "analyzers": [
                "ThreatFox",
                "DNS0_EU_Malicious_Detector",
                "Quad9_Malicious_Detector",
                "OTXQuery",
                "Phishtank",
                "CloudFlare_Malicious_Detector",
                "URLhaus",
                "VirusTotal_v3_Get_Observable",
                "PhishingArmy",
                "InQuest_REPdb",
                "GoogleSafebrowsing",
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
        ("playbooks_manager", "0009_alter_playbookconfig_name"),
    ]

    operations = [
        migrations.RunPython(migrate, reverse_migrate),
    ]
