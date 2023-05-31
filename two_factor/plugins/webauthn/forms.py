from hashlib import sha1

from django import forms
from django.conf import settings
from django.urls import reverse_lazy
from django.utils import timezone
from django.utils.module_loading import import_string
from django.utils.translation import gettext_lazy as _
from pydantic.error_wrappers import ValidationError as PydanticValidationError
from webauthn.helpers.exceptions import InvalidAuthenticationResponse
from webauthn.helpers.structs import (
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity,
)

from two_factor.forms import AuthenticationTokenForm, DeviceValidationForm

from .models import WebauthnDevice
from .utils import (
    AuthenticationCredential,
    RegistrationCredential,
    make_credential_creation_options,
    make_credential_request_options,
    verify_authentication_response,
)


class DefaultWebauthnEntitiesFormMixin:
    """
    Mixin to build WebAuthn entities from HttpRequest instances
    """

    @property
    def webauthn_user(self):
        user = self.request.user

        return PublicKeyCredentialUserEntity(
            id=sha1(str(user.pk).encode("utf-8")).hexdigest().encode("utf-8"),
            name=user.get_username(),
            display_name=user.get_full_name() or user.get_username(),
        )

    @property
    def webauthn_rp(self):
        rp_id = (
            settings.TWO_FACTOR_WEBAUTHN_RP_ID or self.request.get_host().split(":")[0]
        )

        return PublicKeyCredentialRpEntity(
            id=rp_id,
            name=settings.TWO_FACTOR_WEBAUTHN_RP_NAME,
        )

    @property
    def webauthn_origin(self):
        scheme = "https" if self.request.is_secure() else "http"
        return "{scheme}://{host}".format(scheme=scheme, host=self.request.get_host())


WebauthnEntitiesFormMixin = import_string(
    settings.TWO_FACTOR_WEBAUTHN_ENTITIES_FORM_MIXIN
)


class WebauthnAuthenticationTokenForm(
    WebauthnEntitiesFormMixin, AuthenticationTokenForm
):
    @property
    def media(self):
        return forms.Media(
            js=(
                "two_factor/js/webauthn_utils.js",
                reverse_lazy("two_factor:webauthn:get_credential"),
            )
        )

    def __init__(self, user, initial_device, request, **kwargs):
        super().__init__(user, initial_device, **kwargs)
        self.request = request

        self.fields["otp_token"] = forms.CharField(
            label=_("Token"),
            widget=forms.PasswordInput(
                attrs={
                    "autofocus": "autofocus",
                    "inputmode": "none",
                    "autocomplete": "one-time-code",
                    "readonly": True,
                }
            ),
        )
        if not self.data:
            key_handle_allow_list = WebauthnDevice.objects.filter(
                user=user
            ).values_list("key_handle", flat=True)
            options, challenge = make_credential_request_options(
                self.webauthn_rp, allowed_credential_ids=key_handle_allow_list
            )

            self.request.session["webauthn_request_options"] = options
            self.request.session["webauthn_request_challenge"] = challenge

    def _verify_token(self, user, token, device=None):
        challenge = self.request.session.pop("webauthn_request_challenge")
        del self.request.session["webauthn_request_options"]

        try:
            credential_id = AuthenticationCredential.parse_raw(token).id
            device = WebauthnDevice.objects.get(user=user, key_handle=credential_id)

            new_sign_count = verify_authentication_response(
                device.public_key,
                device.sign_count,
                self.webauthn_rp,
                self.webauthn_origin,
                challenge,
                token,
            )
        except (
            PydanticValidationError,
            WebauthnDevice.DoesNotExist,
            InvalidAuthenticationResponse,
        ) as exc:
            raise forms.ValidationError(
                _("Entered token is not valid."), code="invalid_token"
            ) from exc

        device.sign_count = new_sign_count
        device.last_used_at = timezone.now()
        device.save()

        return device

    def _chosen_device(self, user):
        return self.initial_device


class WebauthnDeviceValidationForm(WebauthnEntitiesFormMixin, DeviceValidationForm):
    token = forms.CharField(
        label=_("WebAuthn Token"),
        widget=forms.PasswordInput(
            attrs={
                "readonly": "readonly",
                "autocomplete": "one-time-code",
            }
        ),
    )
    idempotent = False

    class Media:
        js = (
            "two_factor/js/webauthn_utils.js",
            reverse_lazy("two_factor:webauthn:create_credential"),
        )

    def __init__(self, device, request, **kwargs):
        super().__init__(device, **kwargs)
        self.request = request

        if not self.data:
            user_key_handles = WebauthnDevice.objects.filter(
                user=request.user
            ).values_list("key_handle", flat=True)
            options, expected_challenge = make_credential_creation_options(
                self.webauthn_user,
                self.webauthn_rp,
                excluded_credential_ids=user_key_handles,
            )

            self.request.session["webauthn_creation_options"] = options
            self.request.session["webauthn_creation_challenge"] = expected_challenge

    def clean_token(self):
        expected_challenge = self.request.session["webauthn_creation_challenge"]
        token = self.cleaned_data["token"]

        try:
            RegistrationCredential.parse_raw(token)
        except PydanticValidationError as exc:
            raise forms.ValidationError(
                _("Entered token is not valid."), code="invalid_token"
            ) from exc

        self.cleaned_data = {
            **self.cleaned_data,
            "expected_rp_id": self.webauthn_rp.id,
            "expected_origin": self.webauthn_origin,
            "expected_challenge": expected_challenge,
        }

        del self.request.session["webauthn_creation_options"]
        del self.request.session["webauthn_creation_challenge"]
        return token
