# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import json
from uuid import uuid4

from django.test import TestCase

from api_app.analyzables_manager.models import Analyzable
from api_app.analyzers_manager.models import AnalyzerConfig, AnalyzerReport
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
        tools_by_name = {t.name: t for t in tools}
        self.search_jobs = tools_by_name["search_jobs"]
        self.get_job_details = tools_by_name["get_job_details"]
        self.summarize_job = tools_by_name["summarize_job"]

    def test_search_jobs_returns_matching(self):
        result = self.search_jobs.invoke({"query": "malware.example.com"})
        data = json.loads(result)
        self.assertEqual(data["errors"], [])
        self.assertEqual(len(data["jobs"]), 1)
        self.assertEqual(data["jobs"][0]["id"], self.job.pk)

    def test_search_jobs_respects_user_isolation(self):
        other_tools = build_tools(user=self.other_user)
        search = {t.name: t for t in other_tools}["search_jobs"]
        result = search.invoke({"query": "malware.example.com"})
        data = json.loads(result)
        ids = [d["id"] for d in data["jobs"]]
        self.assertIn(self.other_job.pk, ids)
        self.assertNotIn(self.job.pk, ids)

    def test_search_jobs_no_results(self):
        result = self.search_jobs.invoke({"query": "nonexistent999"})
        data = json.loads(result)
        self.assertEqual(data["errors"], [])
        self.assertEqual(data["jobs"], [])

    def test_get_job_details_returns_data(self):
        result = self.get_job_details.invoke({"job_id": self.job.pk})
        data = json.loads(result)
        self.assertEqual(data["errors"], [])
        self.assertEqual(data["job"]["id"], self.job.pk)
        self.assertIn("observable_name", data["job"])
        self.assertIn("status", data["job"])

    def test_get_job_details_forbidden_other_user(self):
        result = self.get_job_details.invoke({"job_id": self.other_job.pk})
        data = json.loads(result)
        self.assertIsNone(data["job"])
        self.assertTrue(data["errors"])
        self.assertIn("not found or not accessible", data["errors"][0])

    def test_summarize_job_formats_output(self):
        result = self.summarize_job.invoke({"job_id": self.job.pk})
        data = json.loads(result)
        self.assertEqual(data["errors"], [])
        self.assertIn(f"Job #{self.job.pk}", data["summary"])
        self.assertIn("malware.example.com", data["summary"])
        self.assertIn("Status", data["summary"])

    def test_summarize_job_failed_reports_use_report_status(self):
        # Regression: analyzer report status uses ReportStatus (uppercase). Only the
        # non-SUCCESS report must show up under "Failed".
        config_ok, config_ko = list(AnalyzerConfig.objects.all()[:2])
        AnalyzerReport.objects.create(
            report={},
            job=self.job,
            config=config_ok,
            status=AnalyzerReport.STATUSES.SUCCESS.value,
            task_id=str(uuid4()),
            parameters={},
        )
        AnalyzerReport.objects.create(
            report={},
            job=self.job,
            config=config_ko,
            status=AnalyzerReport.STATUSES.FAILED.value,
            task_id=str(uuid4()),
            parameters={},
        )
        summary = json.loads(self.summarize_job.invoke({"job_id": self.job.pk}))["summary"]
        self.assertIn(config_ko.name, summary)
        self.assertNotIn(config_ok.name, summary)

    def test_search_jobs_invalid_status_reports_error(self):
        result = self.search_jobs.invoke({"status": "not_a_status"})
        data = json.loads(result)
        self.assertTrue(any("Unknown status" in e for e in data["errors"]))

    def test_search_jobs_valid_status_filters(self):
        result = self.search_jobs.invoke({"status": "reported_without_fails"})
        data = json.loads(result)
        self.assertEqual(data["errors"], [])
        self.assertEqual([d["id"] for d in data["jobs"]], [self.job.pk])

    def test_search_jobs_limit_over_cap_reports_error(self):
        result = self.search_jobs.invoke({"limit": 100})
        data = json.loads(result)
        self.assertTrue(any("maximum 50" in e for e in data["errors"]))

    def tearDown(self):
        Job.objects.filter(user__in=[self.user, self.other_user]).delete()
