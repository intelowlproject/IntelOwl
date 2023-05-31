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
        User.objects.all().delete()
        cls.user = User.objects.create_superuser(username, email, password)
        cls.creds = {
            "username": username,
            "password": password,
        }
        # setup client
        cls.client = APIClient()
        return super().setUpClass()

    @classmethod
    def tearDownClass(cls):
        User.objects.all().delete()
        return super().tearDownClass()
