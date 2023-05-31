# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.contrib.auth import get_user_model
from django.core import mail
from django.core.cache import cache
from django.test import tag
from durin.models import AuthToken, Client
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
        # db clean
        AuthToken.objects.all().delete()
        Client.objects.all().delete()

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
        self.assertEqual(User.objects.count(), 1)

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
        self.assertEqual(User.objects.count(), 1, msg="no new user was created")

    def test_register_no_email_leak_201(self):
        self.assertEqual(User.objects.count(), 1)

        # base check
        with self.assertRaises(
            User.DoesNotExist, msg="testregisteruser doesn't exist right now"
        ):
            User.objects.get(username=self.testregisteruser["username"])

        # register new user
        self.__register_user(body=self.testregisteruser)
        self.assertEqual(User.objects.count(), 2)

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
        self.assertEqual(User.objects.count(), 2, msg="no new user was created")

    def test_register_201(self):
        self.assertEqual(User.objects.count(), 1)

        with self.assertRaises(
            User.DoesNotExist, msg="testregisteruser doesn't exist right now"
        ):
            User.objects.get(username=self.testregisteruser["username"])

        # test
        self.__register_user(body=self.testregisteruser)

        # db assertions
        user = User.objects.get(username=self.testregisteruser["username"])
        self.assertEqual(User.objects.count(), 2)
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
                "recaptcha": "blahblah",
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
                "recaptcha": "blahblah",
            },
        )
        content = response.json()
        msg = (response, content, "check_password should return True")

        self.assertEqual(200, response.status_code, msg=msg)
        user.refresh_from_db()
        self.assertTrue(user.check_password(new_password), msg=msg)

    def test_min_password_lenght_400(self):
        self.assertEqual(User.objects.count(), 1)

        # register new user with invalid password
        body = {
            **self.creds,
            "email": self.testregisteruser["email"],
            "username": "blahblah",
            "first_name": "blahblah",
            "last_name": "blahblah",
            "password": "intelowl",
            "recaptcha": "blahblah",
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
        self.assertEqual(User.objects.count(), 1, msg="no new user was created")

    def test_special_characters_password_400(self):
        self.assertEqual(User.objects.count(), 1)

        # register new user with invalid password
        body = {
            **self.creds,
            "email": self.testregisteruser["email"],
            "username": "blahblah",
            "first_name": "blahblah",
            "last_name": "blahblah",
            "password": "intelowlintelowl$",
            "recaptcha": "blahblah",
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
        self.assertEqual(User.objects.count(), 1, msg="no new user was created")

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


class CheckRegistrationSetupTestCase(CustomOAuthTestCase):
    def test_200_local_setup(self):
        with self.settings(
            DEFAULT_FROM_EMAIL="fake@email.it",
            DEFAULT_EMAIL="fake@email.it",
            STAGE_LOCAL="true",
        ):
            response = self.client.get("/api/auth/check_registration_setup")
            self.assertEqual(response.status_code, 200)

    def test_200_prod_smtp_setup(self):
        with self.settings(
            DEFAULT_FROM_EMAIL="fake@email.it",
            DEFAULT_EMAIL="fake@email.it",
            STAGE_PRODUCTION="true",
            EMAIL_HOST="test",
            EMAIL_HOST_USER="test",
            EMAIL_HOST_PASSWORD="test",
            EMAIL_PORT="test",
            DRF_RECAPTCHA_SECRET_KEY="recaptchakey",
        ):
            response = self.client.get("/api/auth/check_registration_setup")
            self.assertEqual(response.status_code, 200)

    def test_200_prod_ses_setup(self):
        with self.settings(
            DEFAULT_FROM_EMAIL="fake@email.it",
            DEFAULT_EMAIL="fake@email.it",
            STAGE_PRODUCTION="true",
            AWS_SES="true",
            AWS_ACCESS_KEY_ID="test",
            AWS_SECRET_ACCESS_KEY="test",
            DRF_RECAPTCHA_SECRET_KEY="recaptchakey",
        ):
            response = self.client.get("/api/auth/check_registration_setup")
            self.assertEqual(response.status_code, 200)

    def test_501_local_setup(self):
        with self.settings(DEFAULT_FROM_EMAIL="", DEFAULT_EMAIL="", STAGE_LOCAL="true"):
            response = self.client.get("/api/auth/check_registration_setup")
            self.assertEqual(response.status_code, 501)

    def test_501_prod_smtp_setup(self):
        with self.settings(
            DEFAULT_FROM_EMAIL="fake@email.it",
            DEFAULT_EMAIL="fake@email.it",
            STAGE_PRODUCTION="true",
            EMAIL_HOST="",
            EMAIL_HOST_USER="",
            EMAIL_HOST_PASSWORD="",
            EMAIL_PORT="",
            DRF_RECAPTCHA_SECRET_KEY="fake",
        ):
            response = self.client.get("/api/auth/check_registration_setup")
            self.assertEqual(response.status_code, 501)

    def test_501_prod_ses_setup(self):
        with self.settings(
            DEFAULT_FROM_EMAIL="fake@email.it",
            DEFAULT_EMAIL="fake@email.it",
            STAGE_PRODUCTION="true",
            AWS_SES="true",
            AWS_ACCESS_KEY_ID="",
            AWS_SECRET_ACCESS_KEY="",
            DRF_RECAPTCHA_SECRET_KEY="fake",
        ):
            response = self.client.get("/api/auth/check_registration_setup")
            self.assertEqual(response.status_code, 501)
