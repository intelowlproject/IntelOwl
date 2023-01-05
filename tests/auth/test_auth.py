from django.contrib.auth import get_user_model
from django.core import mail
from django.core.cache import cache
from django.test import tag
from durin.models import AuthToken, Client
from rest_email_auth.models import EmailConfirmation
from rest_framework.reverse import reverse

from . import CustomOAuthTestCase

User = get_user_model()
login_uri = reverse("auth_login")
logout_uri = reverse("auth_logout")
register_uri = reverse("auth_register")
verify_email_uri = reverse("auth_verify-email")
resend_verificaton_uri = reverse("auth_resend-verification")


@tag("api", "user")
class TestUserAuth(CustomOAuthTestCase):
    def setUp(self):
        # test data
        self.testregisteruser = {
            "email": "testregisteruser@test.com",
            "username": "testregisteruser",
            "first_name": "testregisteruser",
            "last_name": "testregisteruser",
            "password": "testregisteruser",
            "profile": {
                "company_name": "companytest",
                "company_role": "intelowl test",
                "twitter_handle": "@fake",
                "discover_from": "other",
            },
        }
        mail.outbox = []
        return super().setUp()

    def tearDown(self):
        # cache clear (for throttling)
        cache.clear()
        # db clean
        AuthToken.objects.all().delete()
        Client.objects.all().delete()
        return super().tearDown()

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

    def test_register_username_taken_400(self):
        # get current num of users
        num_users_prev = User.objects.count()

        # In CI, recaptcha protection is disabled so we can pass any value
        body = {
            **self.creds,
            "first_name": "blahblah",
            "last_name": "blahblah",
            "email": self.testregisteruser["email"],
            "recaptcha": "blahblah",
        }

        response = self.client.post(register_uri, body)
        content = response.json()
        msg = (
            response,
            content,
            "self.user already exists so unique username validation will fail.",
        )

        # response assertions
        self.assertEqual(400, response.status_code, msg=msg)
        self.assertIn(
            "A user with that username already exists.",
            content["errors"]["username"],
            msg=msg,
        )
        # db assertions
        self.assertEqual(
            num_users_prev, User.objects.count(), msg="no new user was created"
        )

    def test_register_no_email_leak_201(self):

        # base check
        with self.assertRaises(
            User.DoesNotExist, msg="testregisteruser doesn't exist right now"
        ):
            User.objects.get(username=self.testregisteruser["username"])

        # register new user
        self.__register_user(body=self.testregisteruser)

        # get current num of users
        num_users_prev = User.objects.count()

        # 2nd registration for same email returns 201
        # only as to not leak registered emails
        body = {
            "email": self.testregisteruser["email"],
            "profile": self.testregisteruser["profile"],
            "username": "blahblah",
            "first_name": "blahblah",
            "last_name": "blahblah",
            "password": "averystrongpassword",
        }
        self.__register_user(body=body)

        # db assertions
        self.assertEqual(
            num_users_prev, User.objects.count(), msg="no new user was created"
        )

    def test_register_201(self):
        with self.assertRaises(
            User.DoesNotExist, msg="testregisteruser doesn't exist right now"
        ):
            User.objects.get(username=self.testregisteruser["username"])

        # test
        self.__register_user(body=self.testregisteruser)

        # db assertions
        user = User.objects.get(username=self.testregisteruser["username"])
        self.assertFalse(
            user.is_active, msg="newly registered user must have is_active=False"
        )

    def test_verify_email_200(self):
        # register new user
        self.__register_user(body=self.testregisteruser)

        # db assertions
        user = User.objects.get(username=self.testregisteruser["username"])
        self.assertFalse(
            user.is_active, msg="newly registered user must have is_active=False"
        )

        # get EmailConfirmation instance that was created after registration
        email_confirmation_obj = EmailConfirmation.objects.get(
            email=user.email_addresses.first()
        )

        # send verify email request
        response = self.client.post(
            verify_email_uri, {"key": email_confirmation_obj.key}
        )

        content = response.json()
        msg = (response, content, "User should now be verified")

        # email assertions
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(
            mail.outbox[0].subject, "IntelOwl - Please Verify Your Email Address"
        )
        self.assertEqual(mail.outbox[0].to[0], "testregisteruser@test.com")

        # response assertions
        self.assertEqual(200, response.status_code, msg=msg)

        # db assertions
        user.refresh_from_db()
        self.assertFalse(
            user.is_active, msg="even after verification is_active must be False"
        )

    def test_resend_verification_email_200(self):
        # register new user
        # send first verify email request
        self.__register_user(body=self.testregisteruser)

        # request second verification email
        response = self.client.post(
            resend_verificaton_uri,
            {
                "email": self.testregisteruser["email"],
                "recaptcha": "blahblah",
            },
        )
        content = response.json()
        msg = (response, content)

        # email assertions
        self.assertEqual(len(mail.outbox), 2)
        self.assertEqual(
            mail.outbox[0].subject, "IntelOwl - Please Verify Your Email Address"
        )
        self.assertEqual(mail.outbox[0].to[0], "testregisteruser@test.com")
        self.assertEqual(
            mail.outbox[1].subject, "IntelOwl - Please Verify Your Email Address"
        )
        self.assertEqual(mail.outbox[1].to[0], "testregisteruser@test.com")

        self.assertEqual(200, response.status_code, msg=msg)
        self.assertEqual(self.testregisteruser["email"], content["email"], msg=msg)

    # utils
    def __register_user(self, body: dict):
        # In CI, recaptcha protection is disabled so we can pass any value
        response = self.client.post(
            register_uri, {**body, "recaptcha": "blahblah"}, format="json"
        )
        content = response.json()
        msg = (response, content)

        # response assertions
        self.assertEqual(201, response.status_code, msg=msg)
        self.assertEqual(content["username"], body["username"], msg=msg)
        self.assertEqual(content["email"], body["email"], msg=msg)
        self.assertFalse(
            content["is_active"], msg="newly registered user must have is_active=False"
        )
