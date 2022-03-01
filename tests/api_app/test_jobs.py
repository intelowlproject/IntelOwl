# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import os

from rest_framework.reverse import reverse

from api_app.analyzers_manager.constants import ObservableTypes
from api_app.models import Job

from .. import CustomAPITestCase

jobs_list_uri = reverse("jobs-list")
agg_status_uri = reverse("jobs-aggregate-status")
agg_type_uri = reverse("jobs-aggregate-type")
agg_observable_classification_uri = reverse("jobs-aggregate-observable-classification")
agg_file_mimetype_uri = reverse("jobs-aggregate-file-mimetype")
agg_observable_name_uri = reverse("jobs-aggregate-observable-name")
agg_file_name_uri = reverse("jobs-aggregate-file-name")


class JobViewsetTests(CustomAPITestCase):
    def setUp(self):
        super().setUp()
        self.job, _ = Job.objects.get_or_create(
            **{
                "user": self.superuser,
                "is_sample": False,
                "observable_name": os.environ.get("TEST_IP"),
                "md5": os.environ.get("TEST_MD5"),
                "observable_classification": "ip",
                "analyzers_requested": [],
                "connectors_requested": [],
            }
        )
        self.job2, _ = Job.objects.get_or_create(
            **{
                "user": self.superuser,
                "is_sample": True,
                "md5": "test.file",
                "file_name": "test.file",
                "file_mimetype": "application/x-dosexec",
                "analyzers_requested": [],
                "connectors_requested": [],
            }
        )

    def test_list_200(self):
        response = self.client.get(jobs_list_uri)
        content = response.json()
        msg = (response, content)

        self.assertEqual(200, response.status_code, msg=msg)
        self.assertIn("count", content, msg=msg)
        self.assertIn("total_pages", content, msg=msg)
        self.assertIn("results", content, msg=msg)

    def test_retrieve_200(self):
        response = self.client.get(f"{jobs_list_uri}/{self.job.id}")
        content = response.json()
        msg = (response, content)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(content["id"], self.job.id, msg=msg)
        self.assertEqual(content["status"], self.job.status, msg=msg)

    def test_delete_204(self):
        self.assertEqual(Job.objects.count(), 2)
        response = self.client.delete(f"{jobs_list_uri}/{self.job.id}")
        self.assertEqual(response.status_code, 204)
        self.assertEqual(Job.objects.count(), 1)

    def test_delete_403(self):
        # create a new job which does not belong to authed user
        job = Job.objects.create(status=Job.Status.REPORTED_WITHOUT_FAILS)
        response = self.client.delete(f"{jobs_list_uri}/{job.id}")
        content = response.json()
        msg = (response, content, "PermissionDenied")

        self.assertEqual(response.status_code, 403, msg=msg)

    # @action endpoints

    def test_kill_204(self):
        job = Job.objects.create(status=Job.Status.RUNNING, user=self.superuser)
        self.assertEqual(job.status, Job.Status.RUNNING)
        uri = reverse("jobs-kill", args=[job.pk])
        response = self.client.patch(uri)
        job.refresh_from_db()

        self.assertEqual(response.status_code, 204)
        self.assertEqual(job.status, Job.Status.KILLED)

    def test_kill_400(self):
        # create a new job whose status is not "running"
        job = Job.objects.create(
            status=Job.Status.REPORTED_WITHOUT_FAILS, user=self.superuser
        )
        uri = reverse("jobs-kill", args=[job.pk])
        response = self.client.patch(uri)
        content = response.json()
        msg = (response, content)

        self.assertEqual(response.status_code, 400, msg=msg)
        self.assertDictEqual(
            content["errors"], {"detail": "Job is not running"}, msg=msg
        )

    def test_kill_403(self):
        # create a new job which does not belong to authed user
        job = Job.objects.create(status=Job.Status.RUNNING)
        uri = reverse("jobs-kill", args=[job.pk])
        response = self.client.patch(uri)
        content = response.json()
        msg = (response, content, "PermissionDenied")

        self.assertEqual(response.status_code, 403, msg=msg)

    # aggregation endpoints

    def test_agg_status_200(self):
        resp = self.client.get(agg_status_uri)
        content = resp.json()
        msg = (resp, content)

        self.assertEqual(resp.status_code, 200, msg)
        for field in ["date", *Job.Status.values]:
            self.assertIn(
                field,
                content[0],
                msg=msg,
            )

    def test_agg_type_200(self):
        resp = self.client.get(agg_type_uri)
        content = resp.json()
        msg = (resp, content)

        self.assertEqual(resp.status_code, 200, msg)
        self.assertEqual(resp.status_code, 200, msg)
        for field in ["date", "file", "observable"]:
            self.assertIn(
                field,
                content[0],
                msg=msg,
            )

    def test_agg_observable_classification_200(self):
        resp = self.client.get(agg_observable_classification_uri)
        content = resp.json()
        msg = (resp, content)

        self.assertEqual(resp.status_code, 200, msg)
        for field in ["date", *ObservableTypes.values]:
            self.assertIn(
                field,
                content[0],
                msg=msg,
            )

    def test_agg_file_mimetype_200(self):
        resp = self.client.get(agg_file_mimetype_uri)
        content = resp.json()
        msg = (resp, content)

        self.assertEqual(resp.status_code, 200, msg)
        for field in ["date", *content["values"]]:
            self.assertIn(
                field,
                content["aggregation"][0],
                msg=msg,
            )

    def test_agg_observable_name_200(self):
        resp = self.client.get(agg_observable_name_uri)
        content = resp.json()
        msg = (resp, content)

        self.assertEqual(resp.status_code, 200, msg)
        print(content)
        for field in content["values"]:
            self.assertIn(
                field,
                content["aggregation"],
                msg=msg,
            )

    def test_agg_file_name_200(self):
        resp = self.client.get(agg_file_name_uri)
        content = resp.json()
        msg = (resp, content)

        self.assertEqual(resp.status_code, 200, msg)
        for field in content["values"]:
            self.assertIn(
                field,
                content["aggregation"],
                msg=msg,
            )
