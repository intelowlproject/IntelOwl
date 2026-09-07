from django.db import migrations
from django.db.models import Value
from django.db.models.functions import Replace

OLD_URL = (
    "https://intelowl.readthedocs.io/en/latest/"
    "Advanced-Configuration.html#opencti"
)
NEW_URL = (
    "https://intelowlproject.github.io/docs/IntelOwl/"
    "advanced_configuration/#opencti"
)


def update_opencti_description(apps, schema_editor):
    AnalyzerConfig = apps.get_model("analyzers_manager", "AnalyzerConfig")
    AnalyzerConfig.objects.filter(
        name="OpenCTI",
        description__contains=OLD_URL,
    ).update(
        description=Replace(
            "description", Value(OLD_URL), Value(NEW_URL)
        )
    )


class Migration(migrations.Migration):

    dependencies = [
        ("analyzers_manager", "0196_data_model_phishing_lists"),
    ]

    operations = [
        migrations.RunPython(
            update_opencti_description,
            migrations.RunPython.noop,
        ),
    ]
