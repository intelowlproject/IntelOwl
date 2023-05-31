import django.core.validators
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="PhoneDevice",
            fields=[
                (
                    "id",
                    models.AutoField(
                        verbose_name="ID",
                        serialize=False,
                        auto_created=True,
                        primary_key=True,
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
                    "number",
                    models.CharField(
                        max_length=16,
                        verbose_name="number",
                        validators=[
                            django.core.validators.RegexValidator(
                                regex="^(\\+|00)",
                                message="Please enter a valid phone number,\
                                          including your country code "
                                "starting with + or 00.",
                                code="invalid-phone-number",
                            )
                        ],
                    ),
                ),
                (
                    "key",
                    models.CharField(help_text="Hex-encoded secret key", max_length=40),
                ),
                (
                    "method",
                    models.CharField(
                        max_length=4,
                        verbose_name="method",
                        choices=[("call", "Phone Call"), ("sms", "Text Message")],
                    ),
                ),
                (
                    "user",
                    models.ForeignKey(
                        help_text="The user that this device belongs to.",
                        to=settings.AUTH_USER_MODEL,
                        on_delete=models.CASCADE,
                    ),
                ),
            ],
            options={
                "abstract": False,
            },
            bases=(models.Model,),
        ),
    ]
