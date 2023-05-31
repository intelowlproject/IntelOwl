from django.utils.translation import gettext_lazy as _
from otp_yubikey.models import RemoteYubikeyDevice, ValidationService

from two_factor.plugins.registry import MethodBase

from .forms import YubiKeyAuthenticationForm, YubiKeyDeviceForm


class YubikeyMethod(MethodBase):
    code = "yubikey"
    verbose_name = _("YubiKey")

    def get_devices(self, user):
        return RemoteYubikeyDevice.objects.filter(user=user)

    def recognize_device(self, device):
        return isinstance(device, RemoteYubikeyDevice)

    def get_setup_forms(self, *args):
        return {"yubikey": YubiKeyDeviceForm}

    def get_device_from_setup_data(self, request, setup_data, **kwargs):
        public_id = setup_data.get("yubikey", {}).get("token", "")[:-32]
        try:
            service = ValidationService.objects.get(name="default")
        except ValidationService.DoesNotExist:
            raise KeyError("No ValidationService found with name 'default'")
        except ValidationService.MultipleObjectsReturned:
            raise KeyError("Multiple ValidationService found with name 'default'")
        return RemoteYubikeyDevice(
            name="default", user=request.user, public_id=public_id, service=service
        )

    def get_token_form_class(self):
        return YubiKeyAuthenticationForm

    def get_action(self, device):
        return _("Use your Yubikey device")

    def get_verbose_action(self, device):
        return _("Please use your Yubikey device.")
