from django import template
from django.utils.translation import gettext as _

from ..utils import format_phone_number as format_phone_number_utils
from ..utils import mask_phone_number as mask_phone_number_utils

register = template.Library()


@register.filter
def mask_phone_number(number):
    return mask_phone_number_utils(number)


mask_phone_number.__doc__ = mask_phone_number_utils.__doc__


@register.filter
def format_phone_number(number):
    return format_phone_number_utils(number)


format_phone_number.__doc__ = format_phone_number_utils.__doc__


@register.filter
def device_action(device):
    """
    Generates an actionable text for a :class:
    `~two_factor.plugins.phonenumber.models.PhoneDevice`.

    Examples:

    * Send text message to `+31 * ******58`
    * Call number `+31 * ******58`
    """
    assert device.__class__.__name__ == "PhoneDevice"
    number = mask_phone_number_utils(format_phone_number_utils(device.number))
    if device.method == "sms":
        return _("Send text message to %s") % number
    elif device.method == "call":
        return _("Call number %s") % number
    raise NotImplementedError("Unknown method: %s" % device.method)
