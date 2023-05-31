from django.utils.translation import gettext_lazy as _
from django_otp.plugins.otp_email.models import EmailDevice

from two_factor.plugins.registry import MethodBase

from .forms import AuthenticationTokenForm, DeviceValidationForm, EmailForm
from .utils import mask_email


class EmailMethod(MethodBase):
    code = "email"
    verbose_name = _("Email")

    def get_devices(self, user):
        return EmailDevice.objects.devices_for_user(user).all()

    def recognize_device(self, device):
        return isinstance(device, EmailDevice)

    def get_setup_forms(self, wizard):
        forms = {}
        if not wizard.request.user.email:
            forms[self.code] = EmailForm
        forms["validation"] = DeviceValidationForm
        return forms

    def get_device_from_setup_data(self, request, setup_data, **kwargs):
        if setup_data and not request.user.email:
            request.user.email = setup_data.get("email").get("email")
            request.user.save(update_fields=["email"])
        device = EmailDevice.objects.devices_for_user(request.user).first()
        if not device:
            device = EmailDevice(user=request.user, name="default")
        return device

    def get_token_form_class(self):
        return AuthenticationTokenForm

    def get_action(self, device):
        email = device.email or device.user.email
        return _("Send email to %s") % (email and mask_email(email) or None,)

    def get_verbose_action(self, device):
        return _("We sent you an email, please enter the token we sent.")
