# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from rest_framework.reverse import reverse

from api_app.models import Tag

from .. import CustomAPITestCase

tags_list_uri = reverse("tags-list")


class TagViewsetTests(CustomAPITestCase):
    def setUp(self):
        super().setUp()
        self.client.force_authenticate(user=self.superuser)
        self.tag, _ = Tag.objects.get_or_create(label="testlabel1", color="#FF5733")

    def test_create_201(self):
        self.assertEqual(Tag.objects.count(), 1)
        data = {"label": "testlabel2", "color": "#91EE28"}
        response = self.client.post(tags_list_uri, data)
        content = response.json()
        msg = (response, content)

        self.assertEqual(response.status_code, 201, msg=msg)
        self.assertDictContainsSubset(data, content, msg=msg)
        self.assertEqual(Tag.objects.count(), 2)

    def test_list_200(self):
        response = self.client.get(tags_list_uri)
        content = response.json()
        msg = (response, content)

        self.assertEqual(response.status_code, 200, msg=msg)

    def test_retrieve_200(self):
        response = self.client.get(f"{tags_list_uri}/{self.tag.id}")
        content = response.json()
        msg = (response, content)

        self.assertEqual(response.status_code, 200, msg=msg)

    def test_update_200(self):
        new_data = {"label": "newTestLabel", "color": "#765A54"}
        response = self.client.put(f"{tags_list_uri}/{self.tag.id}", new_data)
        content = response.json()
        msg = (response, content)

        self.assertEqual(response.status_code, 200, msg=msg)
        self.assertDictContainsSubset(new_data, content, msg=msg)

    def test_delete_204(self):
        self.assertEqual(Tag.objects.count(), 1)
        response = self.client.delete(f"{tags_list_uri}/{self.tag.id}")

        self.assertEqual(response.status_code, 204)
        self.assertEqual(Tag.objects.count(), 0)
