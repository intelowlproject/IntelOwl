from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("analyzers_manager", "0178_add_local_db_models_torproject"),
    ]

    operations = [
        migrations.CreateModel(
            name="TorDanMeUKNode",
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
                    "ip",
                    models.GenericIPAddressField(db_index=True, unique=True),
                ),
            ],
            options={
                "verbose_name": "Tor DanMeUK Node",
                "verbose_name_plural": "Tor DanMeUK Nodes",
            },
        ),
    ]
