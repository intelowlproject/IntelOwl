from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _
from phonenumber_field.phonenumber import to_python


def validate_international_phonenumber(value):
    phone_number = to_python(value)
    if phone_number and not phone_number.is_valid():
        raise ValidationError(
            validate_international_phonenumber.message, code="invalid"
        )


validate_international_phonenumber.message = _(
    "Please enter a valid phone number, including your country code "
    "starting with + or 00."
)
