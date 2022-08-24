from django.contrib.auth import get_user_model
from django.test import tag
from durin.models import AuthToken, Client
from rest_framework.reverse import reverse

from . import CustomOAuthTestCase

User = get_user_model()
login_uri = reverse("auth_login")
logout_uri = reverse("auth_logout")


@tag("api", "user")
class TestUserAuth(CustomOAuthTestCase):
    def setUp(self):
        AuthToken.objects.all().delete()
        return super().setUp()

    def test_login_200(self):
        self.assertEqual(AuthToken.objects.count(), 0)

        response = self.client.post(login_uri, self.creds)
        content = response.json()
        msg = (response, content)

        self.assertEqual(response.status_code, 200, msg=msg)
        self.assertIn("token", response.data, msg=msg)
        self.assertIn("expiry", response.data, msg=msg)
        self.assertIn("user", response.data, msg=msg)
        self.assertIn(self.user.USERNAME_FIELD, response.data["user"], msg=msg)

        self.assertEqual(AuthToken.objects.count(), 1)

    def test_logout_204(self):
        self.assertEqual(AuthToken.objects.count(), 0)

        token = AuthToken.objects.create(
            user=self.user,
            client=Client.objects.create(name="test_logout_deletes_keys"),
        )
        self.assertEqual(AuthToken.objects.count(), 1)

        self.client.credentials(HTTP_AUTHORIZATION=("Token %s" % token.token))
        response = self.client.post(logout_uri)

        self.assertEqual(response.status_code, 204, msg=(response))
        self.assertEqual(
            AuthToken.objects.count(), 0, "other tokens should remain after logout"
        )
