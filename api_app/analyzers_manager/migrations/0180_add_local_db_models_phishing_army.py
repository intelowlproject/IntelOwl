from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("analyzers_manager", "0179_add_local_db_models_tor_danmeuk"),
    ]

    operations = [
        migrations.CreateModel(
            name="PhishingArmyDomain",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "domain",
                    models.CharField(max_length=255, db_index=True, unique=True),
                ),
            ],
            options={
                "verbose_name": "Phishing Army Domain",
                "verbose_name_plural": "Phishing Army Domains",
            },
        ),
    ]
