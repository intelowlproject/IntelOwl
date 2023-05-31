from django.apps import AppConfig
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured

from two_factor.plugins.registry import registry


class TwoFactorWebauthnConfig(AppConfig):
    name = "two_factor.plugins.webauthn"
    label = "two_factor_webauthn"
    verbose_name = "Django Two Factor Authentication - WebAuthn Method"
    url_prefix = "webauthn"
    default_auto_field = "django.db.models.AutoField"

    defaults = {
        "TWO_FACTOR_WEBAUTHN_RP_NAME": None,
        "TWO_FACTOR_WEBAUTHN_AUTHENTICATOR_ATTACHMENT": None,
        "TWO_FACTOR_WEBAUTHN_PREFERRED_TRANSPORTS": None,
        "TWO_FACTOR_WEBAUTHN_UV_REQUIREMENT": "discouraged",
        "TWO_FACTOR_WEBAUTHN_ATTESTATION_CONVEYANCE": "none",
        "TWO_FACTOR_WEBAUTHN_PEM_ROOT_CERTS_BYTES_BY_FMT": None,
        "TWO_FACTOR_WEBAUTHN_ENTITIES_FORM_MIXIN": "two_factor.plugins.webauthn.forms.\
        DefaultWebauthnEntitiesFormMixin",
        "TWO_FACTOR_WEBAUTHN_RP_ID": None,
        "TWO_FACTOR_WEBAUTHN_THROTTLE_FACTOR": 1,
    }

    def ready(self):
        try:
            from webauthn.helpers.structs import AttestationConveyancePreference
        except ImportError:
            raise ImproperlyConfigured(
                "'webauthn' must be installed to be able to use the webauthn plugin."
            )

        for name, default in self.defaults.items():
            value = getattr(settings, name, default)
            setattr(settings, name, value)

        if not settings.TWO_FACTOR_WEBAUTHN_RP_NAME:
            raise ImproperlyConfigured(
                "The TWO_FACTOR_WEBAUTHN_RP_NAME setting must not be empty."
            )

        if (
            settings.TWO_FACTOR_WEBAUTHN_ATTESTATION_CONVEYANCE
            == AttestationConveyancePreference.ENTERPRISE
        ):
            raise ImproperlyConfigured(
                f"'{AttestationConveyancePreference.ENTERPRISE}' is not a supported"
                " value for TWO_FACTOR_WEBAUTHN_ATTESTATION_CONVEYANCE."
            )

        from .method import WebAuthnMethod

        registry.register(WebAuthnMethod())
