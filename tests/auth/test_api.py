# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.contrib.auth import get_user_model
from django.test import tag
from rest_framework.authtoken.models import Token
from rest_framework.reverse import reverse

from . import CustomOAuthTestCase

User = get_user_model()

api_uri = reverse("auth_apiaccess")


@tag("api", "user")
class TestUserAuth(CustomOAuthTestCase):
    def test_get_token_unauthorized(self):
        response = self.client.get(api_uri)
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json(), {"detail": "Authentication credentials were not provided."})

    def test_get_token_no_token_available(self):
        self.assertEqual(Token.objects.count(), 0)
        self.client.force_authenticate(self.user)
        response = self.client.get(api_uri)
        self.assertEqual(response.status_code, 404)

    def test_get_token_available(self):
        token, _ = Token.objects.get_or_create(user=self.user)
        self.client.force_authenticate(self.user)
        response = self.client.get(api_uri)
        self.assertEqual(response.status_code, 200)
        response_data = response.json()
        self.assertEqual(response_data["key"], token.key)
        self.assertEqual(response_data["created"], token.created.strftime("%Y-%m-%dT%H:%M:%S.%fZ"))

    def test_create_token_unauthorized(self):
        response = self.client.post(api_uri)
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json(), {"detail": "Authentication credentials were not provided."})

    def test_create_token_already_exist(self):
        Token.objects.get_or_create(user=self.user)
        self.client.force_authenticate(self.user)
        response = self.client.post(api_uri)
        self.assertEqual(response.status_code, 400)
        response_data = response.json()
        self.assertCountEqual(response_data, {"errors": ["An API token was already issued to you."]})

    def test_create_token(self):
        self.client.force_authenticate(self.user)
        response = self.client.post(api_uri)
        self.assertEqual(response.status_code, 201)
        response_data = response.json()
        token = Token.objects.get(user=self.user)
        self.assertEqual(response_data["key"], token.key)
        self.assertEqual(response_data["created"], token.created.strftime("%Y-%m-%dT%H:%M:%S.%fZ"))

    def test_delete_token_unauthorized(self):
        Token.objects.get_or_create(user=self.user)
        response = self.client.delete(api_uri)
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json(), {"detail": "Authentication credentials were not provided."})
        self.assertEqual(Token.objects.count(), 1)

    def test_delete_token_unavailable(self):
        self.assertEqual(Token.objects.count(), 0)
        self.client.force_authenticate(self.user)
        response = self.client.delete(api_uri)
        self.assertEqual(response.status_code, 404)

    def test_delete_token(self):
        Token.objects.get_or_create(user=self.user)
        self.client.force_authenticate(self.user)
        response = self.client.delete(api_uri)
        self.assertEqual(response.status_code, 204)
        self.assertEqual(Token.objects.count(), 0)
