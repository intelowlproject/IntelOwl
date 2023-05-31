from django.utils.translation import gettext_lazy as _

from two_factor.plugins.registry import MethodBase

from .forms import WebauthnAuthenticationTokenForm, WebauthnDeviceValidationForm
from .models import WebauthnDevice
from .utils import verify_registration_response


class WebAuthnMethod(MethodBase):
    code = "webauthn"
    verbose_name = _("WebAuthn")

    def get_devices(self, user):
        return user.webauthn_keys.all()

    def get_other_authentication_devices(self, user, main_device):
        # authentication is attempted on all WebAuthn devices at the same time
        # if main_device is a WebAuthn device then WebAuthn is the primary method
        # and there are no "other" WebAuthn devices
        if self.recognize_device(main_device):
            return []

        for device in self.get_devices(user):
            # first WebAuthn device found is enough to trigger on all of them at
            # the same time
            return [device]
        return []

    def recognize_device(self, device):
        return isinstance(device, WebauthnDevice)

    def get_setup_forms(self, *args):
        return {self.code: WebauthnDeviceValidationForm}

    def get_device_from_setup_data(self, request, setup_data, **kwargs):
        webauthn_setup_data = setup_data.get("webauthn")
        if webauthn_setup_data is None:
            return None

        expected_rp_id = webauthn_setup_data["expected_rp_id"]
        expected_origin = webauthn_setup_data["expected_origin"]
        expected_challenge = webauthn_setup_data["expected_challenge"]
        token = webauthn_setup_data["token"]

        public_key, key_handle, sign_count = verify_registration_response(
            expected_rp_id, expected_origin, expected_challenge, token
        )

        return WebauthnDevice(
            name="default",
            public_key=public_key,
            key_handle=key_handle,
            sign_count=sign_count,
            user=request.user,
        )

    def get_token_form_class(self):
        return WebauthnAuthenticationTokenForm

    def get_action(self, device):
        return _("Authenticate using a WebAuthn-compatible device")

    def get_verbose_action(self, device):
        return _("Please use your WebAuthn-compatible device to authenticate.")
