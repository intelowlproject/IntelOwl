# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

"""Tool-level tests for the verdict summarize_job returns (no LLM, no network)."""

import json
from uuid import uuid4

from django.test import TestCase

from api_app.analyzables_manager.models import Analyzable
from api_app.analyzers_manager.models import AnalyzerConfig, AnalyzerReport
from api_app.chatbot_manager.agent.tools import build_tools
from api_app.chatbot_manager.evaluation import REASON_GENERIC, REASON_NO_EVALUATION
from api_app.choices import TLP, Classification
from api_app.data_model_manager.enums import DataModelEvaluations, DataModelVerdictBuckets
from api_app.data_model_manager.models import DomainDataModel
from api_app.models import Job
from certego_saas.apps.user.models import User


class SummarizeJobVerdictTestCase(TestCase):
    """summarize_job carries IntelOwl's own verdict (PR C fold): no separate evaluate tool."""

    def setUp(self):
        self.user, _ = User.objects.get_or_create(username="chatbot_summ_verdict_user")
        self.analyzable, _ = Analyzable.objects.get_or_create(
            name="verdict-tool.example.com", classification=Classification.DOMAIN
        )
        self.job = Job.objects.create(
            user=self.user,
            analyzable=self.analyzable,
            status=Job.STATUSES.REPORTED_WITHOUT_FAILS,
            tlp=TLP.CLEAR.value,
        )
        self.config = AnalyzerConfig.objects.first()
        tools_by_name = {tool.name: tool for tool in build_tools(user=self.user)}
        self.summarize_job = tools_by_name["summarize_job"]

    def tearDown(self):
        Job.objects.filter(user=self.user).delete()

    def _add_report_with_verdict(self, evaluation, reliability):
        data_model = DomainDataModel.objects.create(evaluation=evaluation, reliability=reliability)
        report = AnalyzerReport.objects.create(
            report={},
            job=self.job,
            config=self.config,
            status=AnalyzerReport.STATUSES.SUCCESS.value,
            task_id=str(uuid4()),
            parameters={},
        )
        report.data_model = data_model
        report.save()
        return report

    def test_summarize_job_includes_the_verdict(self):
        self._add_report_with_verdict(DataModelEvaluations.MALICIOUS.value, 8)
        payload = json.loads(self.summarize_job.invoke({"job_id": self.job.pk}))
        verdict = payload["verdict"]
        self.assertEqual(verdict["bucket"], DataModelVerdictBuckets.MALICIOUS.value)
        self.assertEqual(verdict["evaluation"], DataModelEvaluations.MALICIOUS.value)
        self.assertEqual(verdict["reliability"], 8)
        self.assertIn(DataModelVerdictBuckets.MALICIOUS.value, verdict["headline"])
        self.assertEqual([item["name"] for item in verdict["supporting"]], [self.config.name])
        self.assertEqual(verdict["contradicting"], [])
        self.assertEqual(verdict["silent"], [])
        self.assertEqual(verdict["analyzers_considered"], 1)
        self.assertFalse(verdict["analyst_override"])
        # the metadata summary is unchanged and still present
        self.assertIn(f"Job #{self.job.pk}", payload["summary"])

    def test_headline_is_echoed_into_the_prose_summary(self):
        """The headline is deliberately duplicated in `summary`, not only in `verdict`.

        A live smoke against qwen2.5:3b showed the model reproduces this prose verbatim while
        paraphrasing the structured object away — dropping the reliability and reporting
        contradicting analyzers as silent. Removing this line regresses the narration, so it is
        pinned here rather than left to the reviewer's memory.
        """
        self._add_report_with_verdict(DataModelEvaluations.MALICIOUS.value, 8)
        payload = json.loads(self.summarize_job.invoke({"job_id": self.job.pk}))
        self.assertIn(payload["verdict"]["headline"], payload["summary"])

    def test_summarize_job_without_evaluation_says_so(self):
        payload = json.loads(self.summarize_job.invoke({"job_id": self.job.pk}))
        self.assertEqual(payload["verdict"]["bucket"], DataModelVerdictBuckets.NO_EVALUATION.value)
        self.assertEqual(payload["verdict"]["reason"], REASON_NO_EVALUATION)
        self.assertIsNone(payload["verdict"]["evaluation"])

    def test_summarize_job_generic_observable_has_no_verdict(self):
        generic, _ = Analyzable.objects.get_or_create(
            name="free text observable", classification=Classification.GENERIC
        )
        job = Job.objects.create(
            user=self.user,
            analyzable=generic,
            status=Job.STATUSES.REPORTED_WITHOUT_FAILS,
            tlp=TLP.CLEAR.value,
        )
        payload = json.loads(self.summarize_job.invoke({"job_id": job.pk}))
        self.assertEqual(payload["verdict"]["bucket"], DataModelVerdictBuckets.NO_EVALUATION.value)
        self.assertEqual(payload["verdict"]["reason"], REASON_GENERIC)

    def test_summarize_job_not_visible_returns_null_verdict(self):
        """Tenancy: an invisible job is indistinguishable from a missing one — no verdict leaks."""
        other_user, _ = User.objects.get_or_create(username="chatbot_summ_verdict_other")
        other_job = Job.objects.create(
            user=other_user,
            analyzable=self.analyzable,
            status=Job.STATUSES.REPORTED_WITHOUT_FAILS,
            tlp=TLP.RED.value,
        )
        payload = json.loads(self.summarize_job.invoke({"job_id": other_job.pk}))
        self.assertIsNone(payload["verdict"])
        self.assertIsNone(payload["summary"])
        self.assertTrue(payload["errors"])
        other_job.delete()
