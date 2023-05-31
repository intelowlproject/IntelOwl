from django.conf import settings
from django.shortcuts import redirect, resolve_url
from django.views.decorators.cache import never_cache
from django.views.generic import DeleteView
from django_otp.decorators import otp_required
from django_otp.util import random_hex

from two_factor.forms import DeviceValidationForm
from two_factor.views.utils import IdempotentSessionWizardView, class_view_decorator

from .forms import PhoneNumberMethodForm
from .models import PhoneDevice
from .utils import get_available_phone_methods


@class_view_decorator(never_cache)
@class_view_decorator(otp_required)
class PhoneSetupView(IdempotentSessionWizardView):
    """
    View for configuring a phone number for receiving tokens.

    A user can have multiple backup :class:`~two_factor.models.PhoneDevice`
    for receiving OTP tokens. If the primary phone number is not available, as
    the battery might have drained or the phone is lost, these backup phone
    numbers can be used for verification.
    """

    template_name = "two_factor/core/phone_register.html"
    success_url = settings.LOGIN_REDIRECT_URL
    form_list = (
        ("setup", PhoneNumberMethodForm),
        ("validation", DeviceValidationForm),
    )
    key_name = "key"

    def get(self, request, *args, **kwargs):
        """
        Start the setup wizard. Redirect if no phone methods available.
        """
        if not get_available_phone_methods():
            return redirect(self.success_url)
        return super().get(request, *args, **kwargs)

    def done(self, form_list, **kwargs):
        """
        Store the device and redirect to profile page.
        """
        self.get_device(user=self.request.user, name="backup").save()
        return redirect(self.success_url)

    def render_next_step(self, form, **kwargs):
        """
        In the validation step, ask the device to generate a challenge.
        """
        next_step = self.steps.next
        if next_step == "validation":
            self.get_device().generate_challenge()
        return super().render_next_step(form, **kwargs)

    def get_form_kwargs(self, step=None):
        """
        Provide the device to the DeviceValidationForm.
        """
        if step == "validation":
            return {"device": self.get_device()}
        return {}

    def get_device(self, **kwargs):
        """
        Uses the data from the setup step and generated key to recreate device.
        """
        kwargs = kwargs or {}
        kwargs.update(self.storage.validated_step_data.get("setup", {}))
        return PhoneDevice(key=self.get_key(), **kwargs)

    def get_key(self):
        """
        The key is preserved between steps and stored as ascii in the session.
        """
        if self.key_name not in self.storage.extra_data:
            self.storage.extra_data[self.key_name] = random_hex(20)
        return self.storage.extra_data[self.key_name]

    def get_context_data(self, form, **kwargs):
        kwargs.setdefault("cancel_url", resolve_url(self.success_url))
        return super().get_context_data(form, **kwargs)


@class_view_decorator(never_cache)
@class_view_decorator(otp_required)
class PhoneDeleteView(DeleteView):
    """
    View for removing a phone number used for verification.
    """

    success_url = settings.LOGIN_REDIRECT_URL

    def get_queryset(self):
        return self.request.user.phonedevice_set.filter(name="backup")

    def get_success_url(self):
        return resolve_url(self.success_url)
