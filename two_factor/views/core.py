import logging
import time
import warnings
from base64 import b32encode
from binascii import unhexlify
from inspect import signature
from uuid import uuid4

import django_otp
import qrcode
import qrcode.image.svg
from django.conf import settings
from django.contrib.auth import REDIRECT_FIELD_NAME, login
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.sites.shortcuts import get_current_site
from django.core.signing import BadSignature
from django.forms import Form, ValidationError
from django.http import Http404, HttpResponse, HttpResponseRedirect
from django.shortcuts import redirect, resolve_url
from django.urls import reverse
from django.utils.decorators import method_decorator
from django.utils.functional import cached_property
from django.utils.http import url_has_allowed_host_and_scheme
from django.utils.module_loading import import_string
from django.utils.translation import gettext as _
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.debug import sensitive_post_parameters
from django.views.generic import FormView, TemplateView
from django.views.generic.base import View
from django_otp import devices_for_user
from django_otp.decorators import otp_required
from django_otp.plugins.otp_static.models import StaticDevice, StaticToken
from django_otp.util import random_hex

from two_factor import signals
from two_factor.plugins.phonenumber.utils import get_available_phone_methods
from two_factor.plugins.registry import registry
from two_factor.utils import totp_digits
from two_factor.views.mixins import OTPRequiredMixin

from ..forms import (
    AuthenticationTokenForm,
    BackupTokenForm,
    DeviceValidationForm,
    MethodForm,
    TOTPDeviceForm,
)
from ..utils import default_device, get_otpauth_url
from .utils import (
    IdempotentSessionWizardView,
    class_view_decorator,
    get_remember_device_cookie,
    validate_remember_device_cookie,
)

try:
    from django.contrib.auth.views import RedirectURLMixin
except ImportError:  # django<4.1
    from django.contrib.auth.views import (
        SuccessURLAllowedHostsMixin as RedirectURLMixin,
    )
logger = logging.getLogger(__name__)

REMEMBER_COOKIE_PREFIX = getattr(
    settings, "TWO_FACTOR_REMEMBER_COOKIE_PREFIX", "remember-cookie_"
)


class LoginView(RedirectURLMixin, IdempotentSessionWizardView):
    """
    View for handling the login process, including OTP verification.

    The login process is composed like a wizard. The first step asks for the
    user's credentials. If the credentials are correct, the wizard proceeds to
    the OTP verification step. If the user has a default OTP device configured,
    that device is asked to generate a token (send sms / call phone) and the
    user is asked to provide the generated token. The backup devices are also
    listed, allowing the user to select a backup device for verification.
    """

    AUTH_STEP = "auth"
    TOKEN_STEP = "token"
    BACKUP_STEP = "backup"
    FIRST_STEP = AUTH_STEP

    template_name = "two_factor/core/login.html"
    form_list = (
        (AUTH_STEP, AuthenticationForm),
        (TOKEN_STEP, AuthenticationTokenForm),
        (BACKUP_STEP, BackupTokenForm),
    )
    redirect_authenticated_user = False
    storage_name = "two_factor.views.utils.LoginStorage"

    def has_token_step(self):
        return default_device(self.get_user()) and not self.remember_agent

    def has_backup_step(self):
        return (
            default_device(self.get_user())
            and self.TOKEN_STEP not in self.storage.validated_step_data
            and not self.remember_agent
        )

    @cached_property
    def expired(self):
        login_timeout = getattr(settings, "TWO_FACTOR_LOGIN_TIMEOUT", 600)
        if login_timeout == 0:
            return False
        expiration_time = (
            self.storage.data.get("authentication_time", 0) + login_timeout
        )
        return int(time.time()) > expiration_time

    condition_dict = {
        TOKEN_STEP: has_token_step,
        BACKUP_STEP: has_backup_step,
    }
    redirect_field_name = REDIRECT_FIELD_NAME

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.user_cache = None
        self.device_cache = None
        self.cookies_to_delete = []
        self.show_timeout_error = False

    def post(self, *args, **kwargs):
        """
        The user can select a particular device to challenge, being the backup
        devices added to the account.
        """
        wizard_goto_step = self.request.POST.get("wizard_goto_step", None)

        if wizard_goto_step == self.FIRST_STEP:
            self.storage.reset()

        if self.expired and self.step_requires_authentication(self.steps.current):
            logger.info(
                "User's authentication flow has timed out. The user "
                "has been redirected to the initial auth form."
            )
            self.storage.reset()
            self.show_timeout_error = True
            return self.render_goto_step(self.FIRST_STEP)

        # Generating a challenge doesn't require to validate the form.
        if "challenge_device" in self.request.POST:
            self.storage.data["challenge_device"] = self.request.POST[
                "challenge_device"
            ]
            return self.render_goto_step(self.TOKEN_STEP)

        response = super().post(*args, **kwargs)
        return self.delete_cookies_from_response(response)

    def done(self, form_list, **kwargs):
        """
        Login the user and redirect to the desired page.
        """

        # Check if remember cookie should be set after login
        current_step_data = self.storage.get_step_data(self.steps.current)
        remember = bool(
            current_step_data and current_step_data.get("token-remember") == "on"
        )

        login(self.request, self.get_user())

        redirect_to = self.get_success_url()

        device = getattr(self.get_user(), "otp_device", None)
        response = redirect(redirect_to)

        if device:
            signals.user_verified.send(
                sender=__name__,
                request=self.request,
                user=self.get_user(),
                device=device,
            )

            # Set a remember cookie if activated

            if getattr(settings, "TWO_FACTOR_REMEMBER_COOKIE_AGE", None) and remember:
                # choose a unique cookie key to remember devices for multiple users in
                # the same browser
                cookie_key = REMEMBER_COOKIE_PREFIX + str(uuid4())
                cookie_value = get_remember_device_cookie(
                    user=self.get_user(), otp_device_id=device.persistent_id
                )
                response.set_cookie(
                    cookie_key,
                    cookie_value,
                    max_age=settings.TWO_FACTOR_REMEMBER_COOKIE_AGE,
                    domain=getattr(settings, "TWO_FACTOR_REMEMBER_COOKIE_DOMAIN", None),
                    path=getattr(settings, "TWO_FACTOR_REMEMBER_COOKIE_PATH", "/"),
                    secure=getattr(
                        settings, "TWO_FACTOR_REMEMBER_COOKIE_SECURE", False
                    ),
                    httponly=getattr(
                        settings, "TWO_FACTOR_REMEMBER_COOKIE_HTTPONLY", True
                    ),
                    samesite=getattr(
                        settings, "TWO_FACTOR_REMEMBER_COOKIE_SAMESITE", "Lax"
                    ),
                )
            return response

        # If the user does not have a device.
        elif OTPRequiredMixin.is_otp_view(self.request.GET.get("next")):
            if self.request.GET.get("next"):
                self.request.session["next"] = self.get_success_url()
            return redirect("two_factor:setup")

        return response

    # Copied from django.conrib.auth.views.LoginView (Branch: stable/1.11.x)
    # https://github.com/django/django/blob/58df8aa40fe88f753ba79e091a52f236246260b3/
    # django/contrib/auth/views.py#L63
    def get_success_url(self):
        url = self.get_redirect_url()
        return url or resolve_url(settings.LOGIN_REDIRECT_URL)

    # Copied from django.contrib.auth.views.LoginView (Branch: stable/1.11.x)
    # https://github.com/django/django/blob/58df8aa40fe88f753ba79e091a52f236246260b3/
    # django/contrib/auth/views.py#L67
    def get_redirect_url(self):
        """Return the user-originating redirect URL if it's safe."""
        redirect_to = self.request.POST.get(
            self.redirect_field_name, self.request.GET.get(self.redirect_field_name, "")
        )
        url_is_safe = url_has_allowed_host_and_scheme(
            url=redirect_to,
            allowed_hosts=self.get_success_url_allowed_hosts(),
            require_https=self.request.is_secure(),
        )
        return redirect_to if url_is_safe else ""

    def get_form_kwargs(self, step=None):
        if step is None:
            return {}

        form_class = self.get_form_list()[step]
        form_params = signature(form_class).parameters

        kwargs = {}
        if "user" in form_params:
            kwargs["user"] = self.get_user()
        if "initial_device" in form_params:
            kwargs["initial_device"] = self.get_device(step)
        if "request" in form_params:
            kwargs["request"] = self.request
        return kwargs

    def get_done_form_list(self):
        """
        Return the forms that should be processed during the final step
        """
        # Intentionally do not process the auth form on the final step. We
        # haven't stored this data, and it isn't required to login the user
        form_list = self.get_form_list()
        form_list.pop(self.AUTH_STEP)
        return form_list

    def process_step(self, form):
        """
        Process an individual step in the flow
        """
        # To prevent saving any private auth data to the session store, we
        # validate the authentication form, determine the resulting user, then
        # only store the minimum needed to login that user (the user's primary
        # key and the backend used)
        if self.steps.current == self.AUTH_STEP:
            user = form.is_valid() and form.user_cache
            self.storage.reset()
            self.storage.authenticated_user = user
            self.storage.data["authentication_time"] = int(time.time())

            # By returning None when the user clicks the "back" button to the
            # auth step the form will be blank with validation warnings
            return None

        return super().process_step(form)

    def process_step_files(self, form):
        """
        Process the files submitted from a specific test
        """
        if self.steps.current == self.AUTH_STEP:
            return {}
        return super().process_step_files(form)

    def get_form(self, step=None, **kwargs):
        """
        Returns the form for the step
        """
        if (step or self.steps.current) == self.TOKEN_STEP:
            # Set form class dynamically depending on user device.
            method = registry.method_from_device(self.get_device())
            self.form_list[self.TOKEN_STEP] = method.get_token_form_class()
        form = super().get_form(step=step, **kwargs)
        if self.show_timeout_error:
            form.cleaned_data = getattr(form, "cleaned_data", {})
            form.add_error(
                None,
                ValidationError(_("Your session has timed out. Please login again.")),
            )
        return form

    def get_device(self, step=None):
        """
        Returns the OTP device selected by the user, or his default device.
        """
        if not self.device_cache:
            challenge_device_id = self.request.POST.get(
                "challenge_device"
            ) or self.storage.data.get("challenge_device")
            if challenge_device_id:
                for device in self.get_devices():
                    if device.persistent_id == challenge_device_id:
                        self.device_cache = device
                        break

            if step == self.BACKUP_STEP:
                try:
                    self.device_cache = self.get_user().staticdevice_set.get(
                        name="backup"
                    )
                except StaticDevice.DoesNotExist:
                    pass

            if not self.device_cache:
                self.device_cache = default_device(self.get_user())

        return self.device_cache

    def get_devices(self):
        user = self.get_user()

        devices = []
        for method in registry.get_methods():
            devices += list(method.get_devices(user))
        return devices

    def get_other_devices(self, main_device):
        user = self.get_user()

        other_devices = []
        for method in registry.get_methods():
            other_devices += list(
                method.get_other_authentication_devices(user, main_device)
            )

        return other_devices

    def step_requires_authentication(self, step):
        return step != self.FIRST_STEP

    def render(self, form=None, **kwargs):
        """
        If the user selected a device, ask the device to generate a challenge;
        either making a phone call or sending a text message.
        """
        if self.steps.current == self.TOKEN_STEP:
            form_with_errors = form and form.is_bound and not form.is_valid()
            if not form_with_errors:
                self.get_device().generate_challenge()
        return super().render(form, **kwargs)

    def get_user(self):
        """
        Returns the user authenticated by the AuthenticationForm. Returns False
        if not a valid user; see also issue #65.
        """
        if not self.user_cache:
            self.user_cache = self.storage.authenticated_user
        return self.user_cache

    def get_context_data(self, form, **kwargs):
        """
        Adds user's default and backup OTP devices to the context.
        """
        context = super().get_context_data(form, **kwargs)
        if self.steps.current == self.TOKEN_STEP:
            device = self.get_device()
            context["device"] = device
            context["other_devices"] = self.get_other_devices(device)

            try:
                context["backup_tokens"] = (
                    self.get_user()
                    .staticdevice_set.get(name="backup")
                    .token_set.count()
                )
            except StaticDevice.DoesNotExist:
                context["backup_tokens"] = 0

        if getattr(settings, "LOGOUT_REDIRECT_URL", None):
            context["cancel_url"] = resolve_url(settings.LOGOUT_REDIRECT_URL)
        elif getattr(settings, "LOGOUT_URL", None):
            warnings.warn(
                "LOGOUT_URL has been replaced by LOGOUT_REDIRECT_URL, please "
                "review the URL and update your settings.",
                DeprecationWarning,
            )
            context["cancel_url"] = resolve_url(settings.LOGOUT_URL)
        return context

    @cached_property
    def remember_agent(self):
        """
        Returns True if a user, browser and device is remembered
        using the remember cookie.
        """
        if not getattr(settings, "TWO_FACTOR_REMEMBER_COOKIE_AGE", None):
            return False

        user = self.get_user()
        devices = list(devices_for_user(user))
        for key, value in self.request.COOKIES.items():
            if key.startswith(REMEMBER_COOKIE_PREFIX) and value:
                for device in devices:
                    verify_is_allowed, extra = device.verify_is_allowed()
                    try:
                        if verify_is_allowed and validate_remember_device_cookie(
                            value, user=user, otp_device_id=device.persistent_id
                        ):
                            user.otp_device = device
                            device.throttle_reset()
                            return True
                    except BadSignature:
                        device.throttle_increment()
                        # Remove remember cookies with invalid signature to omit
                        # unnecessary throttling
                        self.cookies_to_delete.append(key)
        return False

    def delete_cookies_from_response(self, response):
        """
        Deletes the cookies_to_delete in the response
        """
        for cookie in self.cookies_to_delete:
            response.delete_cookie(cookie)
        return response

    # Copied from django.contrib.auth.views.LoginView  (Branch: stable/1.11.x)
    # https://github.com/django/django/blob/58df8aa40fe88f753ba79e091a52f236246260b3/
    # django/contrib/auth/views.py#L49
    @method_decorator(sensitive_post_parameters())
    @method_decorator(csrf_protect)
    @method_decorator(never_cache)
    def dispatch(self, request, *args, **kwargs):
        if self.redirect_authenticated_user and self.request.user.is_authenticated:
            redirect_to = self.get_success_url()
            if redirect_to == self.request.path:
                raise ValueError(
                    "Redirection loop for authenticated user detected. Check that "
                    "your LOGIN_REDIRECT_URL doesn't point to a login page."
                )
            return HttpResponseRedirect(redirect_to)
        return super().dispatch(request, *args, **kwargs)


@class_view_decorator(never_cache)
@class_view_decorator(login_required)
class SetupView(RedirectURLMixin, IdempotentSessionWizardView):
    """
    View for handling OTP setup using a wizard.

    The first step of the wizard shows an introduction text, explaining how OTP
    works and why it should be enabled. The user has to select the verification
    method (generator / call / sms) in the second step. Depending on the method
    selected, the third step configures the device. For the generator method, a
    QR code is shown which can be scanned using a mobile phone app and the user
    is asked to provide a generated token. For call and sms methods, the user
    provides the phone number which is then validated in the final step.
    """

    success_url = "two_factor:setup_complete"
    qrcode_url = "two_factor:qr"
    template_name = "two_factor/core/setup.html"
    session_key_name = "django_two_factor-qr_secret_key"
    initial_dict = {}
    form_list = (
        ("welcome", Form),
        ("method", MethodForm),
        # Other forms are dynamically added in get_form_list()
    )

    # Copied from django.contrib.auth.views.LoginView (Branch: stable/1.11.x)
    # https://github.com/django/django/blob/58df8aa40fe88f753ba79e091a52f236246260b3/
    # django/contrib/auth/views.py#L63
    def get_success_url(self):
        url = self.get_redirect_url()
        return url or reverse(self.success_url)

    # Copied from django.contrib.auth.views.LoginView (Branch: stable/1.11.x)
    # https://github.com/django/django/blob/58df8aa40fe88f753ba79e091a52f236246260b3/
    # django/contrib/auth/views.py#L67
    def get_redirect_url(self):
        """Return the user-originating redirect URL if it's safe."""
        redirect_to = self.request.POST.get(
            REDIRECT_FIELD_NAME, self.request.GET.get(REDIRECT_FIELD_NAME, "")
        )
        url_is_safe = url_has_allowed_host_and_scheme(
            url=redirect_to,
            allowed_hosts=self.get_success_url_allowed_hosts(),
            require_https=self.request.is_secure(),
        )
        return redirect_to if url_is_safe else ""

    def get_method(self):
        method_data = self.storage.validated_step_data.get("method", {})
        method_key = method_data.get("method", None)
        return registry.get_method(method_key)

    def get(self, request, *args, **kwargs):
        """
        Start the setup wizard. Redirect if already enabled.
        """
        if default_device(self.request.user):
            return redirect(self.get_success_url())
        return super().get(request, *args, **kwargs)

    def get_form(self, step=None, **kwargs):
        # Until https://github.com/jazzband/django-formtools/pull/62 is merged
        if (step or self.steps.current) not in self.form_list:
            self.form_list = self.get_form_list()
        return super().get_form(step=step, **kwargs)

    def get_form_list(self):
        """
        Check if there is only one method, then skip the MethodForm from form_list.
        """
        form_list = super().get_form_list()

        available_methods = self.get_available_methods()
        if len(available_methods) == 1:
            form_list.pop("method", None)
            method_key = available_methods[0].code
            self.storage.validated_step_data["method"] = {"method": method_key}
        method = self.get_method()
        if method:
            form_list.update(method.get_setup_forms(self))
        else:
            for method in available_methods:
                form_list.update(method.get_setup_forms(self))
        if {"sms", "call"} & set(form_list.keys()):
            form_list["validation"] = DeviceValidationForm
        return form_list

    def get_available_methods(self):
        return registry.get_methods()

    def render_next_step(self, form, **kwargs):
        """
        In the validation step, ask the device to generate a challenge.
        """
        next_step = self.steps.next
        if next_step == "validation":
            try:
                self.get_device().generate_challenge()
                kwargs["challenge_succeeded"] = True
            except Exception:
                logger.exception("Could not generate challenge")
                kwargs["challenge_succeeded"] = False
        return super().render_next_step(form, **kwargs)

    def done(self, form_list, **kwargs):
        """
        Finish the wizard. Save all forms and redirect.
        """
        # Remove secret key used for QR code generation
        try:
            del self.request.session[self.session_key_name]
        except KeyError:
            pass

        method = self.get_method()
        # TOTPDeviceForm
        if method.code == "generator":
            form = [form for form in form_list if isinstance(form, TOTPDeviceForm)][0]
            device = form.save()

        # PhoneNumberForm / YubiKeyDeviceForm / EmailForm /
        # WebauthnDeviceValidationForm
        elif method.code in ("call", "sms", "yubikey", "email", "webauthn"):
            device = self.get_device()
            device.save()

        else:
            raise NotImplementedError("Unknown method '%s'" % method.code)

        django_otp.login(self.request, device)
        return redirect(self.get_success_url())

    def get_form_kwargs(self, step=None):
        if step is None:
            return {}

        form_class = self.get_form_list()[step]
        form_params = signature(form_class).parameters

        kwargs = {}
        if "key" in form_params:
            kwargs["key"] = self.get_key(step)
        if "user" in form_params:
            kwargs["user"] = self.request.user
        if "device" in form_params:
            kwargs["device"] = self.get_device()
        if "request" in form_params:
            kwargs["request"] = self.request

        metadata = self.get_form_metadata(step)
        if metadata:
            kwargs.update(
                {
                    "metadata": metadata,
                }
            )
        return kwargs

    def get_device(self, **kwargs):
        """
        Uses the data from the setup step and generated key to recreate device.

        Only used for call / sms -- generator uses other procedure.
        """
        if not getattr(self, "_device", None):
            method = self.get_method()
            self._device = method.get_device_from_setup_data(
                self.request,
                self.storage.validated_step_data,
                key=self.get_key(method.code),
            )
        return self._device

    def get_key(self, step):
        self.storage.extra_data.setdefault("keys", {})
        if step in self.storage.extra_data["keys"]:
            return self.storage.extra_data["keys"].get(step)
        key = random_hex(20)
        self.storage.extra_data["keys"][step] = key
        return key

    def get_context_data(self, form, **kwargs):
        context = super().get_context_data(form, **kwargs)
        if self.steps.current == "generator":
            key = self.get_key("generator")
            rawkey = unhexlify(key.encode("ascii"))
            b32key = b32encode(rawkey).decode("utf-8")
            issuer = get_current_site(self.request).name
            username = self.request.user.get_username()
            otpauth_url = get_otpauth_url(username, b32key, issuer)
            self.request.session[self.session_key_name] = b32key
            context.update(
                {
                    # used in default template
                    "otpauth_url": otpauth_url,
                    "QR_URL": reverse(self.qrcode_url),
                    "secret_key": b32key,
                    # available for custom templates
                    "issuer": issuer,
                    "totp_digits": totp_digits(),
                }
            )
        elif self.steps.current == "validation":
            context["device"] = self.get_device()
        context["cancel_url"] = resolve_url(settings.LOGIN_REDIRECT_URL)
        return context

    def process_step(self, form):
        if hasattr(form, "metadata"):
            self.storage.extra_data.setdefault("forms", {})
            self.storage.extra_data["forms"][self.steps.current] = form.metadata
        return super().process_step(form)

    def get_form_metadata(self, step):
        self.storage.extra_data.setdefault("forms", {})
        return self.storage.extra_data["forms"].get(step, None)


@class_view_decorator(never_cache)
@class_view_decorator(otp_required)
class BackupTokensView(FormView):
    """
    View for listing and generating backup tokens.

    A user can generate a number of static backup tokens. When the user loses
    its phone, these backup tokens can be used for verification. These backup
    tokens should be stored in a safe location; either in a safe or underneath
    a pillow ;-).
    """

    form_class = Form
    success_url = "two_factor:backup_tokens"
    template_name = "two_factor/core/backup_tokens.html"
    number_of_tokens = 10

    def get_device(self):
        return self.request.user.staticdevice_set.get_or_create(name="backup")[0]

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["device"] = self.get_device()
        return context

    def form_valid(self, form):
        """
        Delete existing backup codes and generate new ones.
        """
        device = self.get_device()
        device.token_set.all().delete()
        for n in range(self.number_of_tokens):
            device.token_set.create(token=StaticToken.random_token())

        return redirect(self.success_url)


@class_view_decorator(never_cache)
@class_view_decorator(otp_required)
class SetupCompleteView(TemplateView):
    """
    View congratulation the user when OTP setup has completed.
    """

    template_name = "two_factor/core/setup_complete.html"

    def get(self, request, *args, **kwargs):
        if request.session.get("next"):
            return redirect(request.session.get("next"))
        return super().get(request, *args, **kwargs)

    def get_context_data(self):
        return {
            "phone_methods": get_available_phone_methods(),
        }


@class_view_decorator(never_cache)
@class_view_decorator(login_required)
class QRGeneratorView(View):
    """
    View returns an SVG image with the OTP token information
    """

    http_method_names = ["get"]
    default_qr_factory = "qrcode.image.svg.SvgPathImage"
    session_key_name = "django_two_factor-qr_secret_key"

    # The qrcode library only supports PNG and SVG for now
    image_content_types = {
        "PNG": "image/png",
        "SVG": "image/svg+xml; charset=utf-8",
    }

    def get_issuer(self):
        return get_current_site(self.request).name

    def get_username(self):
        try:
            username = self.request.user.get_username()
        except AttributeError:
            username = self.request.user.username
        return username

    def get(self, request, *args, **kwargs):
        # Get the data from the session
        try:
            key = self.request.session[self.session_key_name]
        except KeyError:
            raise Http404()

        # Get data for qrcode
        image_factory_string = getattr(
            settings, "TWO_FACTOR_QR_FACTORY", self.default_qr_factory
        )
        image_factory = import_string(image_factory_string)
        content_type = self.image_content_types[image_factory.kind]
        username = self.get_username()

        otpauth_url = get_otpauth_url(
            accountname=username,
            issuer=self.get_issuer(),
            secret=key,
            digits=totp_digits(),
        )

        # Make and return QR code
        img = qrcode.make(otpauth_url, image_factory=image_factory)
        resp = HttpResponse(content_type=content_type)
        img.save(resp)
        return resp
