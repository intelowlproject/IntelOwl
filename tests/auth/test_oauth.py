# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from unittest.mock import Mock, patch
from urllib.parse import parse_qs, urlparse

from django.contrib.auth import get_user_model
from django.contrib.sessions.models import Session
from django.test import tag
from rest_framework import status
from rest_framework.reverse import reverse

from authentication.oauth import oauth
from certego_saas.apps.user.models import User as _UserModel
from intel_owl import secrets

from . import CustomOAuthTestCase

User: _UserModel = get_user_model()


@tag("oauth")
class TestOAuth(CustomOAuthTestCase):
    google_auth_uri = reverse("oauth_google")
    google_auth_callback_uri = reverse("oauth_google_callback")

    def test_google_disabled(self):
        prev_registry = oauth._registry
        oauth._registry = {}
        try:
            response = self.client.get(self.google_auth_uri)
            self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
            self.assertEqual(response.json(), {"detail": "Google OAuth is not configured."})
        finally:
            oauth._registry = prev_registry

    def test_google_enabled(self):
        # IMPORTANT! Without GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET configured
        # this test will fail!
        response = self.client.get(self.google_auth_uri, follow=False)
        self.assertEqual(response.status_code, 302)
        msg = response.url
        expected_redirect_url = urlparse("https://accounts.google.com/o/oauth2/v2/auth")
        response_redirect = urlparse(response.url)
        self.assertEqual(response_redirect.scheme, expected_redirect_url.scheme, msg)
        self.assertEqual(response_redirect.netloc, expected_redirect_url.netloc, msg)
        self.assertEqual(response_redirect.path, expected_redirect_url.path, msg)
        response_redirect_query = parse_qs(response_redirect.query)
        if secrets.get_secret("GOOGLE_CLIENT_ID"):
            self.assertListEqual(
                response_redirect_query.get("client_id"),
                [secrets.get_secret("GOOGLE_CLIENT_ID")],
                msg=msg,
            )
        self.assertListEqual(
            response_redirect_query.get("redirect_uri"),
            [f"http://testserver{self.google_auth_callback_uri}"],
            msg=msg,
        )

    @patch("authentication.views.GoogleLoginCallbackView.validate_and_return_user")
    def test_google_callback(self, mock_validate_and_return_user: Mock):
        self.assertEqual(Session.objects.count(), 0)
        mock_validate_and_return_user.return_value = self.user
        response = self.client.get(self.google_auth_callback_uri, follow=False)
        msg = response.url
        self.assertEqual(response.status_code, 302, msg)
        urlparse(response.url)
        self.assertEqual(Session.objects.count(), 1)
        session = Session.objects.all().first()
        session_data = session.get_decoded()
        self.assertIsNotNone(session_data)
        self.assertIn("_auth_user_id", session_data.keys())
        self.assertEqual(str(self.user.pk), session_data["_auth_user_id"])
