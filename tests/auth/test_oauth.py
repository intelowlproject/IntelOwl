from urllib.parse import parse_qs, urlparse

from django.contrib.auth import get_user_model
from django.test import tag
from rest_framework.reverse import reverse

from certego_saas.apps.user.models import User as _UserModel
from intel_owl import secrets

from . import CustomOAuthTestCase

User: _UserModel = get_user_model()


@tag("oauth")
class TestOAuth(CustomOAuthTestCase):
    def test_google(self):
        google_auth_uri = reverse("oauth_google")
        google_auth_callback_uri = reverse("oauth_google_callback")
        response = self.client.get(google_auth_uri, follow=False)
        msg = response.url
        self.assertEqual(response.status_code, 302, msg)
        expected_redirect_url = urlparse("https://accounts.google.com/o/oauth2/v2/auth")
        response_redirect = urlparse(response.url)
        self.assertEqual(response_redirect.scheme, expected_redirect_url.scheme, msg)
        self.assertEqual(response_redirect.netloc, expected_redirect_url.netloc, msg)
        self.assertEqual(response_redirect.path, expected_redirect_url.path, msg)
        query = parse_qs(response_redirect.query)
        self.assertListEqual(
            query.get("client_id"), [secrets.get_secret("GOOGLE_CLIENT_ID")], msg
        )
        self.assertListEqual(
            query.get("redirect_uri"),
            [f"http://testserver{google_auth_callback_uri}"],
            msg,
        )
