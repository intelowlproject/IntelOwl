from binascii import unhexlify
from time import time

from django import forms
from django.conf import settings
from django.utils.translation import gettext_lazy as _
from django_otp.forms import OTPAuthenticationFormMixin
from django_otp.oath import totp
from django_otp.plugins.otp_totp.models import TOTPDevice

from .plugins.registry import registry
from .utils import totp_digits


class MethodForm(forms.Form):
    method = forms.ChoiceField(label=_("Method"), widget=forms.RadioSelect)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        method = self.fields["method"]
        method.choices = [(m.code, m.verbose_name) for m in registry.get_methods()]
        method.initial = method.choices[0][0]


class DeviceValidationForm(forms.Form):
    token = forms.IntegerField(
        label=_("Token"), min_value=1, max_value=int("9" * totp_digits())
    )

    token.widget.attrs.update(
        {
            "autofocus": "autofocus",
            "inputmode": "numeric",
            "autocomplete": "one-time-code",
        }
    )
    error_messages = {
        "invalid_token": _("Entered token is not valid."),
    }

    def __init__(self, device, **kwargs):
        super().__init__(**kwargs)
        self.device = device

    def clean_token(self):
        token = self.cleaned_data["token"]
        if not self.device.verify_token(token):
            raise forms.ValidationError(self.error_messages["invalid_token"])
        return token


class TOTPDeviceForm(forms.Form):
    token = forms.IntegerField(
        label=_("Token"), min_value=0, max_value=int("9" * totp_digits())
    )

    token.widget.attrs.update(
        {
            "autofocus": "autofocus",
            "inputmode": "numeric",
            "autocomplete": "one-time-code",
        }
    )

    error_messages = {
        "invalid_token": _("Entered token is not valid."),
    }

    def __init__(self, key, user, metadata=None, **kwargs):
        super().__init__(**kwargs)
        self.key = key
        self.tolerance = 1
        self.t0 = 0
        self.step = 30
        self.drift = 0
        self.digits = totp_digits()
        self.user = user
        self.metadata = metadata or {}

    @property
    def bin_key(self):
        """
        The secret key as a binary string.
        """
        return unhexlify(self.key.encode())

    def clean_token(self):
        token = self.cleaned_data.get("token")
        validated = False
        t0s = [self.t0]
        key = self.bin_key
        if "valid_t0" in self.metadata:
            t0s.append(int(time()) - self.metadata["valid_t0"])
        for t0 in t0s:
            for offset in range(-self.tolerance, self.tolerance + 1):
                if totp(key, self.step, t0, self.digits, self.drift + offset) == token:
                    self.drift = offset
                    self.metadata["valid_t0"] = int(time()) - t0
                    validated = True
        if not validated:
            raise forms.ValidationError(self.error_messages["invalid_token"])
        return token

    def save(self):
        return TOTPDevice.objects.create(
            user=self.user,
            key=self.key,
            tolerance=self.tolerance,
            t0=self.t0,
            step=self.step,
            drift=self.drift,
            digits=self.digits,
            name="default",
        )


class DisableForm(forms.Form):
    understand = forms.BooleanField(label=_("Yes, I am sure"))


class AuthenticationTokenForm(OTPAuthenticationFormMixin, forms.Form):
    otp_token = forms.RegexField(
        label=_("Token"),
        regex=r"^[0-9]*$",
        min_length=totp_digits(),
        max_length=totp_digits(),
    )
    otp_token.widget.attrs.update(
        {
            "autofocus": "autofocus",
            "pattern": "[0-9]*",  # hint to show numeric keyboard
            # for on-screen keyboards
            "autocomplete": "one-time-code",
        }
    )

    # Our authentication form has an additional submit button to go to the
    # backup token form. When the `required` attribute is set on an input
    # field, that button cannot be used on browsers that implement html5
    # validation. For now we'll use this workaround, but an even nicer
    # solution would be to move the button outside the `<form>` and into
    # its own `<form>`.
    use_required_attribute = False
    idempotent = False

    def __init__(self, user, initial_device, **kwargs):
        """
        `initial_device` is either the user's default device, or the backup
        device when the user chooses to enter a backup token. The token will
        be verified against all devices, it is not limited to the given
        device.
        """
        super().__init__(**kwargs)
        self.user = user
        self.initial_device = initial_device

        # Add a field to remember this browser.
        if getattr(settings, "TWO_FACTOR_REMEMBER_COOKIE_AGE", None):
            if settings.TWO_FACTOR_REMEMBER_COOKIE_AGE < 3600:
                minutes = int(settings.TWO_FACTOR_REMEMBER_COOKIE_AGE / 60)
                label = _("Don't ask again on this device for %(minutes)i minutes") % {
                    "minutes": minutes
                }
            elif settings.TWO_FACTOR_REMEMBER_COOKIE_AGE < 3600 * 24:
                hours = int(settings.TWO_FACTOR_REMEMBER_COOKIE_AGE / 3600)
                label = _("Don't ask again on this device for %(hours)i hours") % {
                    "hours": hours
                }
            else:
                days = int(settings.TWO_FACTOR_REMEMBER_COOKIE_AGE / 3600 / 24)
                label = _("Don't ask again on this device for %(days)i days") % {
                    "days": days
                }

            self.fields["remember"] = forms.BooleanField(
                required=False, initial=True, label=label
            )

    def clean(self):
        self.clean_otp(self.user)
        return self.cleaned_data


class BackupTokenForm(AuthenticationTokenForm):
    otp_token = forms.CharField(label=_("Token"))
