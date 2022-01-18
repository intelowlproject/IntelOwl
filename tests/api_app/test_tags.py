# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from rest_framework.reverse import reverse

from api_app.models import Tag

from .. import CustomAPITestCase

tags_list_uri = reverse("tags-list")


class TagViewsetTests(CustomAPITestCase):
    def setUp(self):
        super(TagViewsetTests, self).setUp()
        self.client.force_authenticate(user=self.superuser)
        self.tag, _ = Tag.objects.get_or_create(label="testlabel1", color="#FF5733")

    def test_create_201(self):
        self.assertEqual(Tag.objects.count(), 1)
        data = {"label": "testlabel2", "color": "#91EE28"}
        response = self.client.post(tags_list_uri, data)
        self.assertEqual(response.status_code, 201)
        self.assertDictContainsSubset(data, response.json())
        self.assertEqual(Tag.objects.count(), 2)

    def test_list_200(self):
        response = self.client.get(tags_list_uri)
        self.assertEqual(response.status_code, 200)

    def test_retrieve_200(self):
        response = self.client.get(f"{tags_list_uri}/{self.tag.id}")
        self.assertEqual(response.status_code, 200)

    def test_update_200(self):
        new_data = {"label": "newTestLabel", "color": "#765A54"}
        response = self.client.put(f"{tags_list_uri}/{self.tag.id}", new_data)
        self.assertDictContainsSubset(new_data, response.json())
        self.assertEqual(response.status_code, 200)

    def test_delete_204(self):
        self.assertEqual(Tag.objects.count(), 1)
        response = self.client.delete(f"{tags_list_uri}/{self.tag.id}")
        self.assertEqual(response.status_code, 204)
        self.assertEqual(Tag.objects.count(), 0)
