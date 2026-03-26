from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("analyzers_manager", "0181_analyzer_config_phishing_engine_param"),
    ]

    operations = [
        migrations.CreateModel(
            name="TweetFeedItem",
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
                    "value",
                    models.CharField(db_index=True, max_length=512, unique=True),
                ),
                ("details", models.JSONField(default=dict)),
            ],
            options={
                "verbose_name": "TweetFeed Item",
                "verbose_name_plural": "TweetFeed Items",
                "abstract": False,
            },
        ),
    ]
