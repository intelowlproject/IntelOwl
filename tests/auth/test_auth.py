# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.contrib.auth import get_user_model
from django.contrib.sessions.models import Session
from django.core import mail
from django.core.cache import cache
from django.test import tag
from rest_email_auth.models import EmailConfirmation, PasswordResetToken
from rest_framework.reverse import reverse

from . import CustomOAuthTestCase

User = get_user_model()
login_uri = reverse("auth_login")
logout_uri = reverse("auth_logout")
register_uri = reverse("auth_register")
verify_email_uri = reverse("auth_verify-email")
resend_verificaton_uri = reverse("auth_resend-verification")
request_pwd_reset_uri = reverse("auth_request-password-reset")
reset_pwd_uri = reverse("auth_reset-password")
configuration = reverse("auth_configuration")


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

    def tearDown(self):  # skipcq: PYL-R0201
        # cache clear (for throttling)
        cache.clear()

    def test_login_200(self):
        self.assertEqual(Session.objects.count(), 0)
        body = {
            **self.creds,
        }

        response = self.client.post(login_uri, body)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(Session.objects.count(), 1)
        session = Session.objects.all().first()
        session_data = session.get_decoded()
        self.assertIsNotNone(session_data)
        self.assertIn("_auth_user_id", session_data.keys())
        self.assertEqual(str(self.user.pk), session_data["_auth_user_id"])

    def test_logout_204(self):
        self.client.force_authenticate(user=self.user)
        response = self.client.post(logout_uri)
        self.assertEqual(response.status_code, 200)

    def test_register_username_taken_400(self):
        current_users = User.objects.count()

        body = {
            **self.creds,
            "first_name": "blahblah",
            "last_name": "blahblah",
            "email": self.testregisteruser["email"],
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
        self.assertEqual(User.objects.count(), current_users, msg="no new user was created")

    def test_register_no_email_leak_201(self):
        current_users = User.objects.count()

        # base check
        with self.assertRaises(User.DoesNotExist, msg="testregisteruser doesn't exist right now"):
            User.objects.get(username=self.testregisteruser["username"])

        # register new user
        self.__register_user(body=self.testregisteruser)
        self.assertEqual(User.objects.count(), current_users + 1)

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
        self.assertEqual(User.objects.count(), current_users + 1, msg="no new user was created")

    def test_register_201(self):
        current_users = User.objects.count()

        with self.assertRaises(User.DoesNotExist, msg="testregisteruser doesn't exist right now"):
            User.objects.get(username=self.testregisteruser["username"])

        # test
        self.__register_user(body=self.testregisteruser)

        # db assertions
        user = User.objects.get(username=self.testregisteruser["username"])
        self.assertEqual(User.objects.count(), current_users + 1)
        self.assertFalse(user.is_active, msg="newly registered user must have is_active=False")
        self.assertEqual(user.profile.company_name, "companytest")
        user.delete()

    def test_verify_email_200(self):
        # register new user
        self.__register_user(body=self.testregisteruser)

        # db assertions
        user = User.objects.get(username=self.testregisteruser["username"])
        self.assertFalse(user.is_active, msg="newly registered user must have is_active=False")

        # get EmailConfirmation instance that was created after registration
        email_confirmation_obj = EmailConfirmation.objects.get(email=user.email_addresses.first())

        # send verify email request
        response = self.client.post(verify_email_uri, {"key": email_confirmation_obj.key})

        content = response.json()
        msg = (response, content, "User should now be verified")

        # email assertions
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0].subject, "IntelOwl - Please Verify Your Email Address")
        self.assertEqual(mail.outbox[0].to[0], "testregisteruser@test.com")

        # response assertions
        self.assertEqual(200, response.status_code, msg=msg)

        # db assertions
        user.refresh_from_db()
        self.assertFalse(user.is_active, msg="even after verification is_active must be False")

    def test_resend_verification_email_200(self):
        # register new user
        # send first verify email request
        self.__register_user(body=self.testregisteruser)

        # request second verification email
        response = self.client.post(
            resend_verificaton_uri,
            {
                "email": self.testregisteruser["email"],
            },
        )
        content = response.json()
        msg = (response, content)

        # email assertions
        self.assertEqual(len(mail.outbox), 2)
        self.assertEqual(mail.outbox[0].subject, "IntelOwl - Please Verify Your Email Address")
        self.assertEqual(mail.outbox[0].to[0], "testregisteruser@test.com")
        self.assertEqual(mail.outbox[1].subject, "IntelOwl - Please Verify Your Email Address")
        self.assertEqual(mail.outbox[1].to[0], "testregisteruser@test.com")

        self.assertEqual(200, response.status_code, msg=msg)
        self.assertEqual(self.testregisteruser["email"], content["email"], msg=msg)

    def test_password_reset_flow_200(self):
        # register new user
        self.__register_user(body=self.testregisteruser)
        user = User.objects.get(username=self.testregisteruser["username"])
        email_obj = user.email_addresses.first()
        email_obj.is_verified = True  # cant request pwd reset if email not verified
        email_obj.save()

        # step 1: request password reset email
        response = self.client.post(
            request_pwd_reset_uri,
            {
                "email": self.testregisteruser["email"],
            },
        )
        content = response.json()
        msg = (response, content)

        self.assertEqual(200, response.status_code, msg=msg)
        self.assertEqual(self.testregisteruser["email"], content["email"], msg=msg)

        pwd_reset_obj = PasswordResetToken.objects.get(email=email_obj)
        new_password = "new_password_for_test_1234"

        # step 2: reset-password submission
        response = self.client.post(
            reset_pwd_uri,
            {
                "key": pwd_reset_obj.key,
                "password": new_password,
            },
        )
        content = response.json()
        msg = (response, content, "check_password should return True")

        self.assertEqual(200, response.status_code, msg=msg)
        user.refresh_from_db()
        self.assertTrue(user.check_password(new_password), msg=msg)

    def test_min_password_lenght_400(self):
        current_users = User.objects.count()

        # register new user with invalid password
        body = {
            **self.creds,
            "email": self.testregisteruser["email"],
            "username": "blahblah",
            "first_name": "blahblah",
            "last_name": "blahblah",
            "password": "intelowl",
        }

        response = self.client.post(register_uri, body)
        content = response.json()

        # response assertions
        self.assertEqual(400, response.status_code)
        self.assertIn(
            "Invalid password",
            content["errors"]["password"],
        )

        # db assertions
        self.assertEqual(User.objects.count(), current_users, msg="no new user was created")

    def test_special_characters_password_400(self):
        current_users = User.objects.count()

        # register new user with invalid password
        body = {
            **self.creds,
            "email": self.testregisteruser["email"],
            "username": "blahblah",
            "first_name": "blahblah",
            "last_name": "blahblah",
            "password": "intelowlintelowl$",
        }

        response = self.client.post(register_uri, body)
        content = response.json()

        # response assertions
        self.assertEqual(400, response.status_code)
        self.assertIn(
            "Invalid password",
            content["errors"]["password"],
        )

        # db assertions
        self.assertEqual(User.objects.count(), current_users, msg="no new user was created")

    # utils
    def __register_user(self, body: dict):
        response = self.client.post(register_uri, {**body}, format="json")
        content = response.json()
        msg = (response, content)

        # response assertions
        self.assertEqual(201, response.status_code, msg=msg)
        self.assertEqual(content["username"], body["username"], msg=msg)
        self.assertEqual(content["email"], body["email"], msg=msg)
        self.assertFalse(content["is_active"], msg="newly registered user must have is_active=False")


class CheckConfigurationTestCase(CustomOAuthTestCase):
    def setUp(self):
        self.assertEqual(reverse("auth_configuration"), "/api/auth/configuration")

    def test_default_from(self):
        with self.settings(DEFAULT_FROM_EMAIL="", DEFAULT_EMAIL=""):
            response = self.client.get(f"{configuration}?page=register")
            self.assertEqual(response.status_code, 200)
            data = response.json()
            self.assertIn("errors", data)
            self.assertIn("DEFAULT_FROM_EMAIL", data["errors"])
            self.assertIn("DEFAULT_EMAIL", data["errors"])

        with self.settings(
            DEFAULT_FROM_EMAIL="fake@email.it",
            DEFAULT_EMAIL="fake@email.it",
            EMAIL_HOST="test",
            EMAIL_HOST_USER="test",
            EMAIL_HOST_PASSWORD="test",
            EMAIL_PORT="test",
        ):
            response = self.client.get(f"{configuration}?page=register")
            self.assertEqual(response.status_code, 200)
            data = response.json()
            self.assertNotIn("errors", data)
            response = self.client.get(f"{configuration}?page=login")
            self.assertEqual(response.status_code, 200)
            data = response.json()
            self.assertNotIn("errors", data)

    def test_smtp_setup(self):
        with self.settings(
            DEFAULT_FROM_EMAIL="fake@email.it",
            DEFAULT_EMAIL="fake@email.it",
            EMAIL_HOST="test",
            EMAIL_HOST_USER="test",
            EMAIL_HOST_PASSWORD="test",
            EMAIL_PORT="test",
        ):
            response = self.client.get(f"{configuration}?page=register")
            self.assertEqual(response.status_code, 200)
            data = response.json()
            self.assertNotIn("errors", data)

        with self.settings(
            DEFAULT_FROM_EMAIL="fake@email.it",
            DEFAULT_EMAIL="fake@email.it",
            EMAIL_HOST="",
            EMAIL_HOST_USER="",
            EMAIL_HOST_PASSWORD="",
            EMAIL_PORT="",
        ):
            response = self.client.get(f"{configuration}?page=register")
            self.assertEqual(response.status_code, 200)
            data = response.json()
            self.assertIn("errors", data)
            self.assertIn("SMTP backend", data["errors"])

    def test_ses_setup(self):
        with self.settings(
            DEFAULT_FROM_EMAIL="fake@email.it",
            DEFAULT_EMAIL="fake@email.it",
            AWS_SES="true",
            AWS_ACCESS_KEY_ID="test",
            AWS_SECRET_ACCESS_KEY="test",
        ):
            response = self.client.get(f"{configuration}?page=register")
            self.assertEqual(response.status_code, 200)
            data = response.json()
            self.assertNotIn("errors", data)
        with self.settings(
            DEFAULT_FROM_EMAIL="fake@email.it",
            DEFAULT_EMAIL="fake@email.it",
            AWS_SES="true",
            AWS_ACCESS_KEY_ID="",
            AWS_SECRET_ACCESS_KEY="",
        ):
            response = self.client.get(f"{configuration}?page=register")
            self.assertEqual(response.status_code, 200)
            data = response.json()
            self.assertIn("errors", data)
            self.assertIn("AWS SES backend", data["errors"])
