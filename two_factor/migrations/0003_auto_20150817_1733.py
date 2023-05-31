import logging

import phonenumbers
from django.db import migrations
from phonenumber_field.modelfields import PhoneNumberField

logger = logging.getLogger(__name__)


def migrate_phone_numbers(apps, schema_editor):
    PhoneDevice = apps.get_model("two_factor", "PhoneDevice")
    for device in PhoneDevice.objects.all():
        try:
            number = phonenumbers.parse(device.number)
            if not phonenumbers.is_valid_number(number):
                logger.info(
                    "User '%s' has an invalid phone number '%s'."
                    % (device.user, device.number)
                )
            device.number = phonenumbers.format_number(
                number, phonenumbers.PhoneNumberFormat.E164
            )
            device.save()
        except phonenumbers.NumberParseException as e:
            # Do not modify/delete the device, as it worked before.
            # However this might result in issues elsewhere,
            # so do log a warning.
            logger.warning(
                "User '%s' has an invalid phone number '%s': %s.\
                Please resolve this issue, "
                "as it might result in errors." % (device.user, device.number, e)
            )


class Migration(migrations.Migration):

    dependencies = [
        ("two_factor", "0002_auto_20150110_0810"),
    ]

    operations = [
        migrations.RunPython(
            migrate_phone_numbers, reverse_code=migrations.RunPython.noop
        ),
        migrations.AlterField(
            model_name="phonedevice",
            name="number",
            field=PhoneNumberField(max_length=16, verbose_name="number"),
        ),
    ]
