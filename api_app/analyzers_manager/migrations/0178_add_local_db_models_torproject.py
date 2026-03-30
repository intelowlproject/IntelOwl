from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("analyzers_manager", "0177_update_urlscan_observable_supported"),
    ]

    operations = [
        migrations.CreateModel(
            name="TorExitNode",
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
                "verbose_name": "Tor Exit Node",
                "verbose_name_plural": "Tor Exit Nodes",
            },
        ),
    ]