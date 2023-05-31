from django import forms
from django.utils.translation import gettext_lazy as _

from two_factor.forms import AuthenticationTokenForm, DeviceValidationForm


class YubiKeyDeviceForm(DeviceValidationForm):
    token = forms.CharField(label=_("YubiKey"), widget=forms.PasswordInput())

    error_messages = {
        "invalid_token": _("The YubiKey could not be verified."),
    }
    idempotent = False

    def clean_token(self):
        self.device.public_id = self.cleaned_data["token"][:-32]
        return super().clean_token()


class YubiKeyAuthenticationForm(AuthenticationTokenForm):
    # YubiKey generates a OTP of 44 characters (not digits). So if the
    # user's primary device is a YubiKey, replace the otp_token
    # IntegerField with a CharField.
    otp_token = forms.CharField(label=_("YubiKey"), widget=forms.PasswordInput())
