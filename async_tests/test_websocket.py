import abc
import time
from contextlib import asynccontextmanager

from asgiref.sync import sync_to_async
from channels.layers import channel_layers
from channels.testing import WebsocketCommunicator
from django.contrib.auth import get_user_model
from django.test import TransactionTestCase

from api_app.analyzables_manager.models import Analyzable
from api_app.analyzers_manager.constants import TypeChoices
from api_app.analyzers_manager.models import AnalyzerConfig
from api_app.choices import Classification, ParamTypes
from api_app.models import Job, Parameter, PluginConfig, PythonModule
from intel_owl.asgi import application
from intel_owl.tasks import job_set_final_status, run_plugin

User = get_user_model()


class WebsocketTestCase(TransactionTestCase, metaclass=abc.ABCMeta):
    """Class with utilities function for testing websockets"""

    @asynccontextmanager
    async def connect_communicator(self, job_id: int, user: User = None):
        """Connects a websocket communicator to this testcase application,
        forcing given user to be added to its scope.

        To be used as context manager (disconnects on exit)

        :param job_id: id of the job to retrieve data
        :type job_id: int
        :param user: user to connect to websocket
        :type user: auth.user
        :yield: communicator and flag indicationg connection success
        :rtype: tuple(WebsocketCommunicator, bool, int)
        """
        communicator = WebsocketCommunicator(application, f"ws/jobs/{job_id}")
        if user:
            communicator.scope["user"] = user
        connected, subprotocol = await communicator.connect()
        try:
            yield communicator, connected, subprotocol
        finally:
            await communicator.disconnect()

    def _pre_setup(self):
        super()._pre_setup()
        # force channel layers backend reset, this may avoid some RuntimeError
        channel_layers.backends = {}


class JobConsumerTestCase(WebsocketTestCase):
    def setUp(self) -> None:
        self.an = Analyzable.objects.create(
            name="8.8.8.8",
            classification=Classification.IP,
        )

        self.user = User.objects.create(username="websocket_test")
        self.job = Job.objects.create(
            id=1027,
            user=self.user,
            status=Job.STATUSES.REPORTED_WITHOUT_FAILS.value,
            analyzable=self.an,
        )

    def tearDown(self) -> None:
        self.user.delete()
        Job.objects.all().delete()
        Analyzable.objects.all().delete()

    async def test_job_unauthorized(self, *args, **kwargs):
        self.assertEqual(await sync_to_async(Job.objects.filter(id=1027).count)(), 1)
        async with self.connect_communicator(1027) as (_, connected, subprotocol):
            self.assertFalse(connected)
            self.assertEqual(subprotocol, 1008)

    async def test_job_not_exist(self, *args, **kwargs):
        self.assertEqual(await sync_to_async(Job.objects.filter(id=1028).count)(), 0)
        async with self.connect_communicator(1028, self.user) as (
            _,
            connected,
            subprotocol,
        ):
            self.assertFalse(connected)
            self.assertEqual(subprotocol, 4040)

    async def test_job_terminated(self, *args, **kwargs):
        self.assertEqual(await sync_to_async(Job.objects.filter(id=1027).count)(), 1)
        async with self.connect_communicator(1027, self.user) as (
            communicator,
            connected,
            _,
        ):
            self.assertTrue(connected)
            job_report = await communicator.receive_json_from()
            self.assertEqual(job_report["id"], 1027)
            self.assertEqual(job_report["observable_name"], "8.8.8.8")
            self.assertEqual(job_report["status"], Job.STATUSES.REPORTED_WITHOUT_FAILS.value)

    async def test_job_running(self, *args, **kwargs):
        # Note: Sometimes reading from ws (receive_json_from) is too fast:
        # it happens before other part of code send data.
        # The test will be blocked waiting a response from ws that already happened.
        # we need a sleep to wait.
        # in this test happens for the functions: run_plugin set_final_status.
        analyzable = await sync_to_async(Analyzable.objects.create)(
            name="test.com",
            classification=Classification.DOMAIN,
        )
        # setup db
        job = await sync_to_async(Job.objects.create)(
            id=1029,
            user=self.user,
            status=Job.STATUSES.PENDING.value,
            analyzable=analyzable,
        )
        class_dns_python_module, _ = await sync_to_async(PythonModule.objects.get_or_create)(
            base_path="api_app.analyzers_manager.observable_analyzers",
            module="dns.dns_resolvers.classic_dns_resolver.ClassicDNSResolver",
        )
        classic_dns_analyzer_config, _ = await sync_to_async(AnalyzerConfig.objects.get_or_create)(
            name="Classic_DNS",
            python_module=class_dns_python_module,
            type=TypeChoices.OBSERVABLE.value,
            observable_supported=[
                Classification.IP.value,
                Classification.DOMAIN.value,
                Classification.URL.value,
            ],
        )
        analyzer_list = [classic_dns_analyzer_config]
        await sync_to_async(job.analyzers_requested.set)(analyzer_list)
        await sync_to_async(job.analyzers_to_execute.set)(analyzer_list)
        query_type_param = Parameter.objects.filter(
            name="query_type",
            description="Query type against the chosen DNS resolver.",
            python_module=class_dns_python_module,
        )
        if await sync_to_async(query_type_param.count)():
            query_type_param = await sync_to_async(query_type_param.first)()
        else:
            query_type_param = Parameter(
                name="query_type",
                description="Query type against the chosen DNS resolver.",
                python_module=class_dns_python_module,
                type=ParamTypes.STR,
                is_secret=False,
                required=True,
            )
            await sync_to_async(query_type_param.save)()
        plugin_config = PluginConfig(
            owner=self.user,
            for_organization=False,
            value="A",
            analyzer_config=classic_dns_analyzer_config,
            parameter=query_type_param,
            parameter_id=query_type_param.id,
        )
        await sync_to_async(plugin_config.save)()

        async with self.connect_communicator(1029, self.user) as (
            communicator,
            connected,
            _,
        ):
            self.assertTrue(connected)
            time.sleep(1)
            job_report_running = await communicator.receive_json_from()
            self.assertEqual(job_report_running["id"], 1029)
            self.assertEqual(job_report_running["observable_name"], "test.com")
            self.assertEqual(job_report_running["status"], Job.STATUSES.PENDING.value)
            self.assertEqual(job_report_running["analyzer_reports"], [])
            self.assertIsNone(job_report_running["finished_analysis_time"])
            time.sleep(1)
            # run plugin
            await sync_to_async(run_plugin)(
                job_id=1029,
                python_module_pk=class_dns_python_module.pk,
                plugin_config_pk=classic_dns_analyzer_config.pk,
                runtime_configuration={},
                task_id=10,
            )
            time.sleep(1)
            job_analyzer_terminated = await communicator.receive_json_from()
            time.sleep(1)
            self.assertEqual(job_analyzer_terminated["id"], 1029)
            self.assertEqual(job_analyzer_terminated["observable_name"], "test.com")
            self.assertEqual(job_analyzer_terminated["status"], Job.STATUSES.PENDING.value)
            self.assertIsNotNone(job_analyzer_terminated["analyzer_reports"])
            self.assertIsNone(job_analyzer_terminated["finished_analysis_time"])
            # terminate job (force status)
            job.status = Job.STATUSES.REPORTED_WITHOUT_FAILS
            await sync_to_async(job.save)()
            await sync_to_async(job_set_final_status)(1029)
            time.sleep(1)
            job_report_terminated = await communicator.receive_json_from()
            time.sleep(1)
            self.assertEqual(job_report_terminated["id"], 1029)
            self.assertEqual(job_report_terminated["observable_name"], "test.com")
            self.assertEqual(
                job_report_terminated["status"],
                Job.STATUSES.REPORTED_WITHOUT_FAILS.value,
            )
            self.assertIsNotNone(job_report_terminated["analyzer_reports"])
            self.assertIsNotNone(job_report_terminated["finished_analysis_time"])

    async def test_job_killed(self, *args, **kwargs):
        analyzable = await sync_to_async(Analyzable.objects.create)(
            name="test.com",
            classification=Classification.DOMAIN,
        )
        await sync_to_async(Job.objects.create)(
            id=1030,
            user=self.user,
            status=Job.STATUSES.RUNNING.value,
            analyzable=analyzable,
        )

        await sync_to_async(self.client.force_login)(self.user)

        time.sleep(1)
        async with self.connect_communicator(1030, self.user) as (
            communicator,
            connected,
            _,
        ):
            self.assertTrue(connected)
            time.sleep(1)
            job_running = await communicator.receive_json_from()
            self.assertEqual(job_running["id"], 1030)
            self.assertEqual(job_running["observable_name"], "test.com")
            self.assertEqual(job_running["status"], Job.STATUSES.RUNNING.value)

            time.sleep(1)
            await sync_to_async(self.client.patch)("/api/jobs/1030/kill")

            time.sleep(1)
            job_killed = await communicator.receive_json_from()
            self.assertEqual(job_killed["id"], 1030)
            self.assertEqual(job_killed["observable_name"], "test.com")
            self.assertEqual(job_killed["status"], Job.STATUSES.KILLED.value)
