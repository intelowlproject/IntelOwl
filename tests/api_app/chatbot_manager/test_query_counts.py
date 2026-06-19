# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

"""Efficiency (query-count) guards for the chatbot tools.

Each guard asserts a tool's DB query count is invariant to the data dimension that would cause an
N+1 (result count, relation count, tree size) rather than checking a brittle magic number: it runs
the tool against a small and a large instance of that dimension and asserts the same count. This
catches an un-prefetched relation added to a serializer later. No LLM is invoked — the tools are
called directly with seeded data.

`analyze_observable` is intentionally NOT guarded here: its cost is ObservableAnalysisSerializer
validation (platform code resolving analyzers/playbooks/connectors), not the chatbot's own queries,
so a guard there would be a brittle measure of someone else's query plan.
"""

from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

from django.db import connection
from django.test import TestCase, override_settings
from django.test.utils import CaptureQueriesContext

from api_app.analyzables_manager.models import Analyzable
from api_app.analyzers_manager.models import AnalyzerConfig, AnalyzerReport
from api_app.chatbot_manager.agent.tools import build_tools
from api_app.chatbot_manager.models import ChatMessage, ChatSession
from api_app.chatbot_manager.tasks import process_chat_message
from api_app.choices import TLP, Classification
from api_app.investigations_manager.models import Investigation
from api_app.models import Job
from api_app.playbooks_manager.models import PlaybookConfig
from certego_saas.apps.organization.membership import Membership
from certego_saas.apps.organization.organization import Organization
from certego_saas.apps.user.models import User

INMEMORY_CHANNEL_LAYER = {"default": {"BACKEND": "channels.layers.InMemoryChannelLayer"}}

# Generous upper bound for the single-object/single-call guards, where the N+1 dimension is the
# seeded global set and is impractical to vary in a test. It is deliberately well above the real
# (handful) count: an N+1 in per-row serialization would be 100+ queries, far above this budget.
_BOUNDED_QUERY_BUDGET = 10


def _count_queries(operation):
    """Return the number of DB queries `operation()` runs.

    CaptureQueriesContext forces a debug cursor regardless of settings.DEBUG, so this works in the
    normal test environment. Callers warm up once before the first measurement so one-time caches
    (ContentType, organization membership) don't skew the count.
    """
    with CaptureQueriesContext(connection) as ctx:
        operation()
    return len(ctx.captured_queries)


class ToolQueryCountTestCase(TestCase):
    """N+1 guards: a tool's query count must not grow with its result/relation size."""

    def setUp(self):
        self.user, _ = User.objects.get_or_create(username="perf_tool_user")
        # Membership exists so visible_for_user's org branch is exercised (matches the sibling tests).
        self.org, _ = Organization.objects.get_or_create(name="perf tool org")
        Membership.objects.get_or_create(user=self.user, organization=self.org, is_owner=True)
        self.analyzable, _ = Analyzable.objects.get_or_create(
            name="perf.example.com", classification=Classification.DOMAIN
        )
        tools_by_name = {tool.name: tool for tool in build_tools(user=self.user)}
        self.search_jobs = tools_by_name["search_jobs"]
        self.get_job_details = tools_by_name["get_job_details"]
        self.summarize_job = tools_by_name["summarize_job"]
        self.list_investigations = tools_by_name["list_investigations"]
        self.get_investigation_tree = tools_by_name["get_investigation_tree"]
        self.summarize_investigation = tools_by_name["summarize_investigation"]
        self.recommend_playbook = tools_by_name["recommend_playbook"]
        self.list_analyzers = tools_by_name["list_analyzers"]
        self.get_data_model = tools_by_name["get_data_model"]

    def tearDown(self):
        Job.objects.filter(user=self.user).delete()
        Investigation.objects.filter(owner=self.user).delete()
        PlaybookConfig.objects.filter(owner=self.user).delete()
        Membership.objects.filter(organization=self.org).delete()
        self.org.delete()

    def _make_job(self, analyzable=None):
        # Owner-visible job (TLP RED is irrelevant for the owner) reused as the unit of the
        # job-count and investigation-job dimensions.
        return Job.objects.create(
            user=self.user,
            analyzable=analyzable or self.analyzable,
            status=Job.STATUSES.REPORTED_WITHOUT_FAILS,
            tlp=TLP.RED.value,
        )

    def _add_reports(self, job, configs):
        # One AnalyzerReport per (job, config). Distinct configs are required (the pair is unique),
        # so callers pass a slice of the seeded AnalyzerConfig set.
        for config in configs:
            AnalyzerReport.objects.create(
                report={},
                job=job,
                config=config,
                status=AnalyzerReport.STATUSES.SUCCESS.value,
                task_id=str(uuid4()),
                parameters={},
            )

    def _make_playbook(self, name):
        # A user-owned starting playbook supporting DOMAIN, so recommend_playbook("domain") returns it.
        return PlaybookConfig.objects.create(
            name=name,
            description="perf",
            type=[Classification.DOMAIN.value],
            owner=self.user,
            for_organization=False,
            starting=True,
        )

    def test_search_jobs_query_count_is_constant(self):
        self._make_job()
        self.search_jobs.invoke({"limit": 50})  # warm up one-time caches
        small = _count_queries(lambda: self.search_jobs.invoke({"limit": 50}))
        for _ in range(5):
            self._make_job()
        large = _count_queries(lambda: self.search_jobs.invoke({"limit": 50}))
        # select_related("analyzable") + prefetch_related(...) keep this constant; an N+1 in the
        # per-row serializer would make `large` exceed `small`.
        self.assertEqual(small, large)

    def test_get_investigation_tree_query_count_is_constant_in_depth(self):
        inv = Investigation.objects.create(
            owner=self.user, name="perf tree", status=Investigation.STATUSES.CREATED.value
        )
        root = self._make_job()
        inv.jobs.add(root)
        # The baseline root must already be non-leaf: treebeard's get_descendants() short-circuits to
        # an empty queryset (0 queries) for a leaf node, so a leaf baseline would measure the one-time
        # leaf->non-leaf transition (a constant +1) instead of the depth/descendant-count invariant
        # this guard targets. With one child present, the single subtree query is in both
        # measurements and only the descendant count differs between them.
        node = root.add_child(
            user=self.user, analyzable=self.analyzable, status=Job.STATUSES.REPORTED_WITHOUT_FAILS
        )
        self.get_investigation_tree.invoke({"investigation_id": inv.pk})  # warm up
        small = _count_queries(lambda: self.get_investigation_tree.invoke({"investigation_id": inv.pk}))
        # Extend the descendant chain deeper (8 descendants total, 9 nodes < _MAX_NODES; chain depth
        # 8 < _MAX_DEPTH=10). treebeard fetches each root's whole subtree in ONE get_descendants(),
        # rebuilding nesting from the materialized `path`, so the count must not grow with depth.
        for _ in range(7):
            node = node.add_child(
                user=self.user,
                analyzable=self.analyzable,
                status=Job.STATUSES.REPORTED_WITHOUT_FAILS,
            )
        large = _count_queries(lambda: self.get_investigation_tree.invoke({"investigation_id": inv.pk}))
        self.assertEqual(small, large)

    def test_get_job_details_query_count_is_constant_in_reports(self):
        job = self._make_job()
        configs = list(AnalyzerConfig.objects.all()[:6])  # seeded DB has hundreds
        self._add_reports(job, configs[:1])
        self.get_job_details.invoke({"job_id": job.pk})  # warm up
        small = _count_queries(lambda: self.get_job_details.invoke({"job_id": job.pk}))
        self._add_reports(job, configs[1:6])  # 5 more reports, distinct configs
        large = _count_queries(lambda: self.get_job_details.invoke({"job_id": job.pk}))
        # analyzerreports are prefetched + nested-serialized; an N+1 would scale with report count.
        self.assertEqual(small, large)

    def test_summarize_job_query_count_is_constant_in_reports(self):
        job = self._make_job()
        configs = list(AnalyzerConfig.objects.all()[:6])
        self._add_reports(job, configs[:1])
        self.summarize_job.invoke({"job_id": job.pk})  # warm up
        small = _count_queries(lambda: self.summarize_job.invoke({"job_id": job.pk}))
        self._add_reports(job, configs[1:6])
        large = _count_queries(lambda: self.summarize_job.invoke({"job_id": job.pk}))
        self.assertEqual(small, large)

    def test_list_investigations_query_count_is_constant(self):
        Investigation.objects.create(
            owner=self.user, name="perf inv 0", status=Investigation.STATUSES.CREATED.value
        )
        self.list_investigations.invoke({"limit": 50})  # warm up
        small = _count_queries(lambda: self.list_investigations.invoke({"limit": 50}))
        for i in range(5):
            Investigation.objects.create(
                owner=self.user,
                name=f"perf inv {i + 1}",
                status=Investigation.STATUSES.CREATED.value,
            )
        large = _count_queries(lambda: self.list_investigations.invoke({"limit": 50}))
        # The list serializer reads DB columns only (jobs-hitting properties are excluded), so the
        # count must stay constant as the number of investigations grows.
        self.assertEqual(small, large)

    def test_summarize_investigation_query_count_is_constant_in_jobs(self):
        inv = Investigation.objects.create(
            owner=self.user, name="perf summ", status=Investigation.STATUSES.CREATED.value
        )
        inv.jobs.add(self._make_job())
        self.summarize_investigation.invoke({"investigation_id": inv.pk})  # warm up
        small = _count_queries(lambda: self.summarize_investigation.invoke({"investigation_id": inv.pk}))
        for _ in range(5):
            inv.jobs.add(self._make_job())
        large = _count_queries(lambda: self.summarize_investigation.invoke({"investigation_id": inv.pk}))
        # The status breakdown is a single aggregate, so adding jobs must not add queries.
        self.assertEqual(small, large)

    def test_recommend_playbook_query_count_is_constant(self):
        self._make_playbook("perf_pb_0")
        # limit=50 (not the default 10) so neither run is capped: if both were capped at the same
        # size the invariance would hold even WITH an N+1. With 1 vs 6 visible playbooks uncapped,
        # an N+1 in the analyzers/connectors serialization would make `large` exceed `small`.
        self.recommend_playbook.invoke({"classification": "domain", "limit": 50})  # warm up
        small = _count_queries(
            lambda: self.recommend_playbook.invoke({"classification": "domain", "limit": 50})
        )
        for i in range(5):
            self._make_playbook(f"perf_pb_{i + 1}")
        large = _count_queries(
            lambda: self.recommend_playbook.invoke({"classification": "domain", "limit": 50})
        )
        self.assertEqual(small, large)

    def test_list_analyzers_query_count_is_bounded(self):
        # The analyzer dimension is the seeded GLOBAL AnalyzerConfig set (100+), impractical to
        # vary in a test. A bounded assertion is robust here precisely because the set is large:
        # an N+1 in per-row serialization would be 100+ queries, far above this bound.
        self.list_analyzers.invoke({"observable_type": "domain"})  # warm up
        count = _count_queries(lambda: self.list_analyzers.invoke({"observable_type": "domain"}))
        self.assertLess(count, _BOUNDED_QUERY_BUDGET)

    def test_get_data_model_query_count_is_bounded(self):
        # Single object (one job's data model), no list dimension: a small fixed budget catches a
        # newly-added per-call query. A job with no data model returns {} and still exercises the
        # visible_for_user lookup + the nullable GenericForeignKey access.
        job = self._make_job()
        self.get_data_model.invoke({"job_id": job.pk})  # warm up
        count = _count_queries(lambda: self.get_data_model.invoke({"job_id": job.pk}))
        self.assertLess(count, _BOUNDED_QUERY_BUDGET)


@override_settings(CHANNEL_LAYERS=INMEMORY_CHANNEL_LAYER)
class ChatTaskQueryCountTestCase(TestCase):
    """The WS turn loads prior history in a single query, so a turn's query count must not grow
    with conversation length. The agent executor is mocked (no LLM, no real tool calls)."""

    def setUp(self):
        self.user, _ = User.objects.get_or_create(username="perf_task_user")
        self.session = ChatSession.objects.create(user=self.user)

    @patch("api_app.chatbot_manager.tasks.get_channel_layer")
    @patch("api_app.chatbot_manager.agent.agent.build_agent_executor")
    def test_process_chat_message_query_count_is_constant_in_history(self, mock_build, mock_get_layer):
        layer = MagicMock()
        layer.group_send = AsyncMock()
        mock_get_layer.return_value = layer
        executor = MagicMock()
        executor.invoke.return_value = {"output": "ok"}
        executor.tools = []  # handler.tool_names = set(); no real tools needed
        mock_build.return_value = executor

        # Each call persists one user + one assistant message, so history grows naturally.
        process_chat_message(self.session.id, "hi", self.user.id)  # warm up
        small = _count_queries(lambda: process_chat_message(self.session.id, "hi", self.user.id))
        for i in range(20):
            ChatMessage.objects.create(session=self.session, role=ChatMessage.Role.USER, content=f"m{i}")
        large = _count_queries(lambda: process_chat_message(self.session.id, "hi", self.user.id))
        # history.messages loads all prior turns in one query; an N+1 would scale with history size.
        self.assertEqual(small, large)
