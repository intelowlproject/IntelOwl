from unittest import skipUnless

from django.forms import ValidationError
from django.test import RequestFactory, TestCase
from django.urls import reverse

try:
    import webauthn

    from two_factor.plugins.webauthn.forms import (
        WebauthnAuthenticationTokenForm,
        WebauthnDeviceValidationForm,
    )
except ImportError:
    webauthn = None


@skipUnless(webauthn, "package webauthn is not present")
class WebauthnAuthenticationFormTests(TestCase):
    def test_verify_token_with_invalid_token(self):
        request_factory = RequestFactory()
        data = {"otp-token": "invalid-token"}
        request = request_factory.post(reverse("two_factor:login"), data=data)
        request.session = {
            "webauthn_request_challenge": "a-challenge",
            "webauthn_request_options": "some-options",
        }

        form = WebauthnAuthenticationTokenForm(None, None, request, data=data)

        with self.assertRaises(ValidationError) as context:
            form._verify_token(None, "invalid-token")

        self.assertEqual(context.exception.code, "invalid_token")


@skipUnless(webauthn, "package webauthn is not present")
class WebauthnDeviceValidationFormTests(TestCase):
    def test_clean_token_with_invalid_token(self):
        request_factory = RequestFactory()
        data = {"token": "invalid-token"}
        request = request_factory.post(reverse("two_factor:setup"), data=data)
        request.session = {"webauthn_creation_challenge": "a-challenge"}

        form = WebauthnDeviceValidationForm(None, request, data=data)

        self.assertFalse(form.is_valid())
        self.assertEqual(form.error_messages.keys(), {"invalid_token"})
