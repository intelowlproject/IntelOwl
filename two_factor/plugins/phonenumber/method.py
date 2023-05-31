from django.utils.translation import gettext_lazy as _

from two_factor.plugins.registry import MethodBase

from .forms import PhoneNumberForm
from .models import PhoneDevice
from .utils import backup_phones, format_phone_number, mask_phone_number


class PhoneMethodBase(MethodBase):
    def get_devices(self, user):
        return [device for device in backup_phones(user) if device.method == self.code]

    def recognize_device(self, device):
        return isinstance(device, PhoneDevice)

    def get_setup_forms(self, *args):
        return {self.code: PhoneNumberForm}

    def get_device_from_setup_data(self, request, storage_data, **kwargs):
        return PhoneDevice(
            key=kwargs["key"],
            name="default",
            user=request.user,
            method=self.code,
            number=storage_data.get(self.code, {}).get("number"),
        )

    def get_action(self, device):
        number = mask_phone_number(format_phone_number(device.number))
        if device.method == "sms":
            return _("Send text message to %s") % number
        else:
            return _("Call number %s") % number

    def get_verbose_action(self, device):
        if device.method == "sms":
            return _("We sent you a text message, please enter the token we sent.")
        else:
            return _(
                "We are calling your phone right now, please enter the digits you hear."
            )


class PhoneCallMethod(PhoneMethodBase):
    code = "call"
    verbose_name = _("Phone call")


class SMSMethod(PhoneMethodBase):
    code = "sms"
    verbose_name = _("Text message")
