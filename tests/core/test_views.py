from abc import abstractmethod
from typing import Type

from api_app.core.models import AbstractConfig
from certego_saas.apps.organization.membership import Membership
from certego_saas.apps.organization.organization import Organization


class ViewSetTestCaseMixin:
    @classmethod
    @property
    @abstractmethod
    def model_class(cls) -> Type[AbstractConfig]:
        raise NotImplementedError()

    def test_list(self):
        response = self.client.get(self.URL)
        result = response.json()
        self.assertEqual(response.status_code, 200, result)
        self.assertIn("count", result)
        self.assertEqual(result["count"], self.model_class.objects.all().count())
        self.assertIn("results", result)
        self.assertTrue(isinstance(result["results"], list))

        self.client.force_authenticate(None)
        response = self.client.get(self.URL)
        self.assertEqual(response.status_code, 401, response.json())
        self.client.force_authenticate(self.superuser)
        response = self.client.get(self.URL)
        self.assertEqual(response.status_code, 200, response.json())

    def test_get(self):
        plugin = self.model_class.objects.order_by("?").first().pk
        response = self.client.get(f"{self.URL}/{plugin}")
        self.assertEqual(response.status_code, 200, response.json())

        self.client.force_authenticate(None)
        response = self.client.get(f"{self.URL}/{plugin}")
        self.assertEqual(response.status_code, 401, response.json())

        self.client.force_authenticate(self.superuser)
        response = self.client.get(f"{self.URL}/{plugin}")
        self.assertEqual(response.status_code, 200, response.json())

    def test_get_non_existent(self):
        response = self.client.get(f"{self.URL}/NON_EXISTENT")
        self.assertEqual(response.status_code, 404, response.json())

    def test_update(self):
        plugin = self.model_class.objects.order_by("?").first().pk
        response = self.client.patch(f"{self.URL}/{plugin}")
        self.assertEqual(response.status_code, 405, response.json())
        self.client.force_authenticate(self.superuser)
        response = self.client.patch(f"{self.URL}/{plugin}")
        self.assertEqual(response.status_code, 405, response.json())

    def test_delete(self):
        plugin = self.model_class.objects.order_by("?").first().pk
        response = self.client.delete(f"{self.URL}/{plugin}")
        self.assertEqual(response.status_code, 405, response.json())
        self.client.force_authenticate(self.superuser)
        response = self.client.delete(f"{self.URL}/{plugin}")
        self.assertEqual(response.status_code, 405, response.json())

    def test_create(self):
        response = self.client.post(self.URL)
        self.assertEqual(response.status_code, 405, response.json())


class AbstractConfigViewSetTestCaseMixin(ViewSetTestCaseMixin):
    def test_organization_disable(self):
        plugin_pk = self.model_class.objects.order_by("?").first().pk
        org, _ = Organization.objects.get_or_create(name="test")
        response = self.client.post(f"{self.URL}/{plugin_pk}/organization")
        # permission denied
        self.assertEqual(response.status_code, 403, response.json())
        result = response.json()
        self.assertIn("detail", result)
        self.assertEqual(
            result["detail"], "You do not have permission to perform this action."
        )
        m, _ = Membership.objects.get_or_create(
            user=self.user, organization=org, is_owner=False
        )
        response = self.client.post(f"{self.URL}/{plugin_pk}/organization")
        # permission denied
        self.assertEqual(response.status_code, 403, response.json())
        result = response.json()
        self.assertIn("detail", result)
        self.assertEqual(
            result["detail"], "You do not have permission to perform this action."
        )

        m.is_owner = True
        m.save()
        plugin = self.model_class.objects.get(pk=plugin_pk)
        self.assertFalse(plugin.disabled_in_organizations.all().exists())
        response = self.client.post(f"{self.URL}/{plugin_pk}/organization")
        self.assertEqual(response.status_code, 201)
        self.assertTrue(plugin.disabled_in_organizations.all().exists())

        response = self.client.post(f"{self.URL}/{plugin_pk}/organization")
        self.assertEqual(response.status_code, 400, response.json())
        self.assertEqual(1, plugin.disabled_in_organizations.all().count())
        result = response.json()
        self.assertIn("errors", result)
        self.assertIn("detail", result["errors"])
        self.assertEqual(
            result["errors"]["detail"], f"Plugin {plugin.name} already disabled"
        )
        plugin.disabled_in_organizations.set([])
        m.delete()
        org.delete()

    def test_organization_enable(self):
        plugin_pk = self.model_class.objects.order_by("?").first().pk
        org, _ = Organization.objects.get_or_create(name="test")
        response = self.client.delete(f"{self.URL}/{plugin_pk}/organization")
        # permission denied
        self.assertEqual(response.status_code, 403, response.json())
        result = response.json()
        self.assertIn("detail", result)
        self.assertEqual(
            result["detail"], "You do not have permission to perform this action."
        )
        m, _ = Membership.objects.get_or_create(
            user=self.user, organization=org, is_owner=False
        )
        response = self.client.delete(f"{self.URL}/{plugin_pk}/organization")
        result = response.json()
        # permission denied
        self.assertEqual(response.status_code, 403, result)
        self.assertIn("detail", result)
        self.assertEqual(
            result["detail"], "You do not have permission to perform this action."
        )

        m.is_owner = True
        m.save()
        plugin = self.model_class.objects.get(pk=plugin_pk)
        self.assertFalse(plugin.disabled_in_organizations.all().exists())
        response = self.client.delete(f"{self.URL}/{plugin_pk}/organization")
        result = response.json()
        self.assertEqual(response.status_code, 400, result)
        self.assertFalse(plugin.disabled_in_organizations.all().exists())
        self.assertIn("errors", result)
        self.assertIn("detail", result["errors"])
        self.assertEqual(
            result["errors"]["detail"], f"Plugin {plugin.name} already enabled"
        )

        plugin.disabled_in_organizations.add(org)
        response = self.client.delete(f"{self.URL}/{plugin_pk}/organization")
        self.assertEqual(response.status_code, 202)
        self.assertFalse(plugin.disabled_in_organizations.all().exists())
        m.delete()
        org.delete()
