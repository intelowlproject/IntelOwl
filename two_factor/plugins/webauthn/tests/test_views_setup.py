from unittest import mock, skipUnless

from django.test import TestCase
from django.urls import reverse

from tests.utils import UserMixin

try:
    import webauthn
except ImportError:
    webauthn = None


class SetupTest(UserMixin, TestCase):
    def setUp(self):
        super().setUp()
        self.user = self.create_user()
        self.login_user()

    @skipUnless(webauthn, "package webauthn is not present")
    def test_setup_webauthn(self):
        self.assertEqual(0, self.user.webauthn_keys.count())

        response = self.client.post(
            reverse("two_factor:setup"), data={"setup_view-current_step": "welcome"}
        )
        self.assertContains(response, "Method:")

        response = self.client.post(
            reverse("two_factor:setup"),
            data={"setup_view-current_step": "method", "method-method": "webauthn"},
        )
        self.assertContains(response, "Token:")
        session = self.client.session
        self.assertIn("webauthn_creation_options", session.keys())

        response = self.client.post(
            reverse("two_factor:setup"), data={"setup_view-current_step": "webauthn"}
        )
        self.assertEqual(
            response.context_data["wizard"]["form"].errors,
            {"token": ["This field is required."]},
        )

        with mock.patch(
            "two_factor.plugins.webauthn.forms.RegistrationCredential.parse_raw"
        ), mock.patch(
            "two_factor.plugins.webauthn.method.verify_registration_response"
        ) as verify_registration_response:
            verify_registration_response.return_value = (
                "mocked_public_key",
                "mocked_credential_id",
                0,
            )

            response = self.client.post(
                reverse("two_factor:setup"),
                data={
                    "setup_view-current_step": "webauthn",
                    "webauthn-token": "a_valid_token",
                },
            )

        self.assertRedirects(response, reverse("two_factor:setup_complete"))
        self.assertEqual(1, self.user.webauthn_keys.count())
