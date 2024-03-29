# Generated by Django 4.2.8 on 2024-02-01 14:27

import datetime

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):
    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="Investigation",
            options={"verbose_name_plural": "investigations"},
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
                ("for_organization", models.BooleanField(default=False)),
                ("name", models.CharField(max_length=100)),
                ("description", models.TextField(blank=True, default="")),
                ("start_time", models.DateTimeField(default=datetime.datetime.now)),
                ("end_time", models.DateTimeField(blank=True, default=None, null=True)),
                (
                    "status",
                    models.CharField(
                        choices=[
                            ("created", "Created"),
                            ("running", "Running"),
                            ("concluded", "Concluded"),
                        ],
                        default="created",
                        max_length=20,
                    ),
                ),
                (
                    "owner",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="investigations",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
        ),
        migrations.AddIndex(
            model_name="investigation",
            index=models.Index(
                fields=["start_time"], name="investigati_start_t_8c993d_idx"
            ),
        ),
    ]
