import django.db.models.deletion
import django_otp.util
import phonenumber_field.modelfields
from django.conf import settings
from django.db import migrations, models

import two_factor.plugins.phonenumber.models


class Migration(migrations.Migration):
    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ("two_factor", "0008_delete_phonedevice"),
    ]

    operations = [
        migrations.SeparateDatabaseAndState(
            state_operations=[
                migrations.CreateModel(
                    name="PhoneDevice",
                    fields=[
                        (
                            "id",
                            models.AutoField(
                                auto_created=True,
                                primary_key=True,
                                serialize=False,
                                verbose_name="ID",
                            ),
                        ),
                        (
                            "name",
                            models.CharField(
                                help_text="The human-readable name of this device.",
                                max_length=64,
                            ),
                        ),
                        (
                            "confirmed",
                            models.BooleanField(
                                default=True, help_text="Is this device ready for use?"
                            ),
                        ),
                        (
                            "throttling_failure_timestamp",
                            models.DateTimeField(
                                blank=True,
                                default=None,
                                help_text="A timestamp of the last failed \
                                verification attempt. "
                                "Null if last attempt succeeded.",
                                null=True,
                            ),
                        ),
                        (
                            "throttling_failure_count",
                            models.PositiveIntegerField(
                                default=0,
                                help_text="Number of successive failed attempts.",
                            ),
                        ),
                        (
                            "number",
                            phonenumber_field.modelfields.PhoneNumberField(
                                max_length=128, region=None
                            ),
                        ),
                        (
                            "key",
                            models.CharField(
                                default=django_otp.util.random_hex,
                                help_text="Hex-encoded secret key",
                                max_length=40,
                                validators=[
                                    two_factor.plugins.phonenumber.models.key_validator
                                ],
                            ),
                        ),
                        (
                            "method",
                            models.CharField(
                                choices=[
                                    ("call", "Phone Call"),
                                    ("sms", "Text Message"),
                                ],
                                max_length=4,
                                verbose_name="method",
                            ),
                        ),
                        (
                            "user",
                            models.ForeignKey(
                                help_text="The user that this device belongs to.",
                                on_delete=django.db.models.deletion.CASCADE,
                                to=settings.AUTH_USER_MODEL,
                            ),
                        ),
                    ],
                    options={
                        "db_table": "two_factor_phonedevice",
                    },
                ),
            ],
        ),
    ]
