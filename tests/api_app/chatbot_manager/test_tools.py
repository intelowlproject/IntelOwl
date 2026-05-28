# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import json

from django.test import TestCase

from api_app.analyzables_manager.models import Analyzable
from api_app.chatbot_manager.agent.tools import build_tools
from api_app.choices import Classification
from api_app.models import Job
from certego_saas.apps.user.models import User


class SearchJobsToolTestCase(TestCase):
    def setUp(self):
        self.user, _ = User.objects.get_or_create(username="chatbot_tool_user")
        self.other_user, _ = User.objects.get_or_create(username="chatbot_other_user")
        self.analyzable, _ = Analyzable.objects.get_or_create(
            name="malware.example.com",
            classification=Classification.DOMAIN,
        )
        self.job = Job.objects.create(
            user=self.user,
            analyzable=self.analyzable,
            status=Job.STATUSES.REPORTED_WITHOUT_FAILS,
            tlp="GREEN",
        )
        self.other_job = Job.objects.create(
            user=self.other_user,
            analyzable=self.analyzable,
            status=Job.STATUSES.REPORTED_WITHOUT_FAILS,
            tlp="GREEN",
        )
        tools = build_tools(user=self.user)
        self.search_jobs = next(t for t in tools if t.name == "search_jobs")
        self.get_job_details = next(t for t in tools if t.name == "get_job_details")
        self.summarize_job = next(t for t in tools if t.name == "summarize_job")

    def test_search_jobs_returns_matching(self):
        result = self.search_jobs.invoke({"query": "malware.example.com"})
        data = json.loads(result)
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]["id"], self.job.pk)

    def test_search_jobs_respects_user_isolation(self):
        other_tools = build_tools(user=self.other_user)
        search = next(t for t in other_tools if t.name == "search_jobs")
        result = search.invoke({"query": "malware.example.com"})
        data = json.loads(result)
        ids = [d["id"] for d in data]
        self.assertIn(self.other_job.pk, ids)
        self.assertNotIn(self.job.pk, ids)

    def test_search_jobs_no_results(self):
        result = self.search_jobs.invoke({"query": "nonexistent999"})
        self.assertIn("No jobs found", result)

    def test_get_job_details_returns_data(self):
        result = self.get_job_details.invoke({"job_id": self.job.pk})
        data = json.loads(result)
        self.assertEqual(data["id"], self.job.pk)
        self.assertIn("observable_name", data)
        self.assertIn("status", data)

    def test_get_job_details_forbidden_other_user(self):
        result = self.get_job_details.invoke({"job_id": self.other_job.pk})
        self.assertIn("not found or not accessible", result)

    def test_summarize_job_formats_output(self):
        result = self.summarize_job.invoke({"job_id": self.job.pk})
        self.assertIn(f"Job #{self.job.pk}", result)
        self.assertIn("malware.example.com", result)
        self.assertIn("Status", result)

    def tearDown(self):
        Job.objects.filter(user__in=[self.user, self.other_user]).delete()
