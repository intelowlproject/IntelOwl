# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.db import migrations


def add_fullhunt_provider(apps, schema_editor):
    AnalyzerConfig = apps.get_model("api_app", "AnalyzerConfig")
    AnalyzerConfig.objects.update_or_create(
        name="FullHunt",
        defaults={
            "description": "FullHunt is a comprehensive attack surface management platform that provides deep intelligence on domains and subdomains.",
            "module": "FullHunt",
            "supported_observables": ["domain"],
            "configuration": [
                {
                    "name": "api_key",
                    "type": "password",
                    "description": "FullHunt API Key",
                    "required": True,
                },
                {
                    "name": "url",
                    "type": "url",
                    "description": "FullHunt API URL",
                    "required": False,
                    "default": "https://fullhunt.io/api/v1",
                },
            ],
        },
    )


def remove_fullhunt_provider(apps, schema_editor):
    AnalyzerConfig = apps.get_model("api_app", "AnalyzerConfig")
    AnalyzerConfig.objects.filter(name="FullHunt").delete()


class Migration(migrations.Migration):

    dependencies = [
        # IMPORTANT: Ensure this filename exists in your api_app/migrations folder
        ("api_app", "0071_delete_last_elastic_report"),
    ]

    operations = [
        migrations.RunPython(
            add_fullhunt_provider, reverse_code=remove_fullhunt_provider
        ),
    ]
