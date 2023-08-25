from django.contrib.auth import get_user_model
from rest_framework.test import APIClient, APITestCase

User = get_user_model()


class CustomOAuthTestCase(APITestCase):
    @classmethod
    def setUpClass(cls):
        # test data
        username = "john.doe"
        email = "john.doe@example.com"
        password = "hunter2"
        cls.user = User.objects.get_or_create(
            username=username,
            email=email,
            is_superuser=True,
            defaults={"password": password},
        )[0]
        cls.creds = {
            "username": username,
            "password": password,
        }
        # setup client
        cls.client = APIClient()
        return super().setUpClass()

    @classmethod
    def tearDownClass(cls):
        cls.user.delete()
        return super().tearDownClass()
