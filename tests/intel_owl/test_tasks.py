import datetime
from unittest.mock import patch

from django.test import override_settings
from kombu import uuid

from api_app.analyzers_manager.models import AnalyzerConfig, AnalyzerReport
from api_app.choices import PythonModuleBasePaths
from api_app.connectors_manager.models import ConnectorConfig, ConnectorReport
from api_app.ingestors_manager.models import IngestorConfig, IngestorReport
from api_app.models import Job, LastElasticReportUpdate, PythonModule
from api_app.pivots_manager.models import PivotConfig, PivotReport
from api_app.visualizers_manager.models import VisualizerConfig, VisualizerReport
from certego_saas.apps.user.models import User
from intel_owl.tasks import send_plugin_report_to_elastic
from tests import CustomTestCase
from tests.mock_utils import MockResponseNoOp

_now = datetime.datetime(2024, 10, 29, 11, tzinfo=datetime.UTC)


@patch("intel_owl.tasks.now", return_value=_now)
@patch("intel_owl.tasks.connections.get_connection")
class SendElasticTestCase(CustomTestCase):

    def setUp(self):
        self.job = Job.objects.create(
            observable_name="dns.google.com", tlp="AMBER", user=User.objects.first()
        )
        AnalyzerReport.objects.create(  # valid
            config=AnalyzerConfig.objects.get(
                python_module=PythonModule.objects.get(
                    base_path=PythonModuleBasePaths.ObservableAnalyzer.value,
                    module="dns.dns_malicious_detectors.dns0_eu_malicious_detector.DNS0EUMaliciousDetector",
                )
            ),
            job=self.job,
            start_time=datetime.datetime(2024, 10, 29, 10, 49, tzinfo=datetime.UTC),
            end_time=datetime.datetime(2024, 10, 29, 10, 59, tzinfo=datetime.UTC),
            status=AnalyzerReport.Status.FAILED,
            errors=["error"],
            task_id=uuid(),
            parameters={},
        )
        AnalyzerReport.objects.create(  # valid
            config=AnalyzerConfig.objects.get(
                python_module=PythonModule.objects.get(
                    base_path=PythonModuleBasePaths.ObservableAnalyzer.value,
                    module="dns.dns_malicious_detectors.quad9_malicious_detector.Quad9MaliciousDetector",
                )
            ),
            job=self.job,
            start_time=datetime.datetime(2024, 10, 29, 10, 49, tzinfo=datetime.UTC),
            end_time=datetime.datetime(2024, 10, 29, 10, 59, tzinfo=datetime.UTC),
            status=AnalyzerReport.Status.KILLED,
            task_id=uuid(),
            parameters={},
        )
        AnalyzerReport.objects.create(  # too old
            config=AnalyzerConfig.objects.get(
                python_module=PythonModule.objects.get(
                    base_path=PythonModuleBasePaths.ObservableAnalyzer.value,
                    module="dns.dns_resolvers.classic_dns_resolver.ClassicDNSResolver",
                )
            ),
            job=self.job,
            start_time=datetime.datetime(
                2024, 9, 29, 10, 58, 49, tzinfo=datetime.timezone.utc
            ),
            end_time=datetime.datetime(
                2024, 9, 29, 10, 58, 59, tzinfo=datetime.timezone.utc
            ),
            status=AnalyzerReport.Status.SUCCESS,
            report={"observable": "dns.google.com", "malicious": False},
            task_id=uuid(),
            parameters={},
        )
        AnalyzerReport.objects.create(  # invalid status
            config=AnalyzerConfig.objects.get(
                python_module=PythonModule.objects.get(
                    base_path=PythonModuleBasePaths.ObservableAnalyzer.value,
                    module="dns.dns_resolvers.cloudflare_dns_resolver.CloudFlareDNSResolver",
                )
            ),
            job=self.job,
            status=AnalyzerReport.Status.RUNNING,
            start_time=datetime.datetime(2024, 10, 29, 10, 49, tzinfo=datetime.UTC),
            end_time=datetime.datetime(2024, 10, 29, 10, 59, tzinfo=datetime.UTC),
            task_id=uuid(),
            parameters={},
        )
        ConnectorReport.objects.create(
            config=ConnectorConfig.objects.get(
                python_module=PythonModule.objects.get(
                    base_path=PythonModuleBasePaths.Connector.value,
                    module="abuse_submitter.AbuseSubmitter",
                )
            ),
            job=self.job,
            start_time=datetime.datetime(2024, 10, 29, 10, 49, tzinfo=datetime.UTC),
            end_time=datetime.datetime(2024, 10, 29, 10, 59, tzinfo=datetime.UTC),
            status=ConnectorReport.Status.SUCCESS,
            task_id=uuid(),
            report={
                "subject": "Subject",
                "from": "sender@gmail.com",
                "to": "receiver@gmail.com",
                "body": "hello world",
            },
            parameters={},
        )
        IngestorReport.objects.create(  # not want to index
            config=IngestorConfig.objects.get(
                python_module=PythonModule.objects.get(
                    base_path=PythonModuleBasePaths.Ingestor.value,
                    module="malware_bazaar.MalwareBazaar",
                )
            ),
            job=self.job,
            start_time=datetime.datetime(2024, 10, 29, 10, 49, tzinfo=datetime.UTC),
            end_time=datetime.datetime(2024, 10, 29, 10, 59, tzinfo=datetime.UTC),
            status=IngestorReport.Status.SUCCESS,
            task_id=uuid(),
            report={},
            parameters={},
        )
        PivotReport.objects.create(
            config=PivotConfig.objects.filter(
                python_module=PythonModule.objects.get(
                    base_path=PythonModuleBasePaths.Pivot.value,
                    module="compare.Compare",
                )
            ).first(),
            job=self.job,
            start_time=datetime.datetime(2024, 10, 29, 10, 49, tzinfo=datetime.UTC),
            end_time=datetime.datetime(2024, 10, 29, 10, 59, tzinfo=datetime.UTC),
            status=PivotReport.Status.SUCCESS,
            task_id=uuid(),
            report={"job_id": [1], "created": True, "motivation": None},
            parameters={},
        )
        VisualizerReport.objects.create(  # not want to index
            config=VisualizerConfig.objects.get(
                python_module=PythonModule.objects.get(
                    base_path=PythonModuleBasePaths.Visualizer.value,
                    module="dns.DNS",
                )
            ),
            job=self.job,
            start_time=datetime.datetime(2024, 10, 29, 10, 49, tzinfo=datetime.UTC),
            end_time=datetime.datetime(2024, 10, 29, 10, 59, tzinfo=datetime.UTC),
            status=VisualizerReport.Status.SUCCESS,
            task_id=uuid(),
            report={
                "level_position": 1,
                "level_size": "3",
                "elements": {
                    "type": "horizontal_list",
                    "alignment": "around",
                    "values": [],
                },
            },
            parameters={},
        )

    def tearDown(self):
        AnalyzerReport.objects.all().delete()
        ConnectorReport.objects.all().delete()
        IngestorReport.objects.all().delete()
        PivotReport.objects.all().delete()
        VisualizerReport.objects.all().delete()
        LastElasticReportUpdate.objects.all().delete()

    @override_settings(ELASTIC_HOST="https://elasticsearch:9200")
    def test_initial(self, *args, **kwargs):
        self.assertEqual(LastElasticReportUpdate.objects.count(), 0)

        with patch(
            "intel_owl.tasks.bulk",
            return_value=MockResponseNoOp(json_data={}, status_code=200),
        ) as mocked_elastic_bulk:
            send_plugin_report_to_elastic()
            self.assertTrue(mocked_elastic_bulk.assert_called_once)
            mocked_bulk_param = mocked_elastic_bulk.call_args.args[1]
            self.assertEqual(
                mocked_bulk_param,
                [
                    {
                        "_op_type": "index",
                        "_index": "plugin-report-analyzer-report-2024-10-29",
                        "_source": {
                            "config": {"name": "DNS0_EU_Malicious_Detector"},
                            "job": {"id": self.job.id},
                            "start_time": datetime.datetime(
                                2024, 10, 29, 10, 49, tzinfo=datetime.timezone.utc
                            ),
                            "end_time": datetime.datetime(
                                2024, 10, 29, 10, 59, tzinfo=datetime.timezone.utc
                            ),
                            "status": "FAILED",
                            "report": {},
                        },
                    },
                    {
                        "_op_type": "index",
                        "_index": "plugin-report-analyzer-report-2024-10-29",
                        "_source": {
                            "config": {"name": "Quad9_Malicious_Detector"},
                            "job": {"id": self.job.id},
                            "start_time": datetime.datetime(
                                2024, 10, 29, 10, 49, tzinfo=datetime.timezone.utc
                            ),
                            "end_time": datetime.datetime(
                                2024, 10, 29, 10, 59, tzinfo=datetime.timezone.utc
                            ),
                            "status": "KILLED",
                            "report": {},
                        },
                    },
                    {
                        "_op_type": "index",
                        "_index": "plugin-report-connector-report-2024-10-29",
                        "_source": {
                            "config": {"name": "AbuseSubmitter"},
                            "job": {"id": self.job.id},
                            "start_time": datetime.datetime(
                                2024, 10, 29, 10, 49, tzinfo=datetime.timezone.utc
                            ),
                            "end_time": datetime.datetime(
                                2024, 10, 29, 10, 59, tzinfo=datetime.timezone.utc
                            ),
                            "status": "SUCCESS",
                            "report": {
                                "to": "receiver@gmail.com",
                                "body": "hello world",
                                "from": "sender@gmail.com",
                                "subject": "Subject",
                            },
                        },
                    },
                    {
                        "_op_type": "index",
                        "_index": "plugin-report-pivot-report-2024-10-29",
                        "_source": {
                            "config": {"name": "AbuseIpToSubmission"},
                            "job": {"id": self.job.id},
                            "start_time": datetime.datetime(
                                2024, 10, 29, 10, 49, tzinfo=datetime.timezone.utc
                            ),
                            "end_time": datetime.datetime(
                                2024, 10, 29, 10, 59, tzinfo=datetime.timezone.utc
                            ),
                            "status": "SUCCESS",
                            "report": {
                                "job_id": [1],
                                "created": True,
                                "motivation": None,
                            },
                        },
                    },
                ],
            )

        self.assertEqual(
            LastElasticReportUpdate.objects.get().last_update_datetime,
            datetime.datetime(2024, 10, 29, 11, tzinfo=datetime.UTC),
        )

    @override_settings(ELASTIC_HOST="https://elasticsearch:9200")
    def test_update(self, *args, **kwargs):
        LastElasticReportUpdate.objects.create(
            last_update_datetime=_now - datetime.timedelta(minutes=5)
        )
        with patch(
            "intel_owl.tasks.bulk",
            return_value=MockResponseNoOp(json_data={}, status_code=200),
        ) as mocked_elastic_bulk:
            send_plugin_report_to_elastic()
            self.assertTrue(mocked_elastic_bulk.assert_called_once)
            mocked_bulk_param = mocked_elastic_bulk.call_args.args[1]
            self.assertEqual(
                mocked_bulk_param,
                [
                    {
                        "_index": "plugin-report-analyzer-report-2024-10-29",
                        "_op_type": "index",
                        "_source": {
                            "config": {"name": "DNS0_EU_Malicious_Detector"},
                            "end_time": datetime.datetime(
                                2024, 10, 29, 10, 59, tzinfo=datetime.timezone.utc
                            ),
                            "job": {"id": self.job.id},
                            "report": {},
                            "start_time": datetime.datetime(
                                2024, 10, 29, 10, 49, tzinfo=datetime.timezone.utc
                            ),
                            "status": "FAILED",
                        },
                    },
                    {
                        "_index": "plugin-report-analyzer-report-2024-10-29",
                        "_op_type": "index",
                        "_source": {
                            "config": {"name": "Quad9_Malicious_Detector"},
                            "end_time": datetime.datetime(
                                2024, 10, 29, 10, 59, tzinfo=datetime.timezone.utc
                            ),
                            "job": {"id": self.job.id},
                            "report": {},
                            "start_time": datetime.datetime(
                                2024, 10, 29, 10, 49, tzinfo=datetime.timezone.utc
                            ),
                            "status": "KILLED",
                        },
                    },
                    {
                        "_index": "plugin-report-connector-report-2024-10-29",
                        "_op_type": "index",
                        "_source": {
                            "config": {"name": "AbuseSubmitter"},
                            "end_time": datetime.datetime(
                                2024, 10, 29, 10, 59, tzinfo=datetime.timezone.utc
                            ),
                            "job": {"id": self.job.id},
                            "report": {
                                "body": "hello world",
                                "from": "sender@gmail.com",
                                "subject": "Subject",
                                "to": "receiver@gmail.com",
                            },
                            "start_time": datetime.datetime(
                                2024, 10, 29, 10, 49, tzinfo=datetime.timezone.utc
                            ),
                            "status": "SUCCESS",
                        },
                    },
                    {
                        "_index": "plugin-report-pivot-report-2024-10-29",
                        "_op_type": "index",
                        "_source": {
                            "config": {"name": "AbuseIpToSubmission"},
                            "end_time": datetime.datetime(
                                2024, 10, 29, 10, 59, tzinfo=datetime.timezone.utc
                            ),
                            "job": {"id": self.job.id},
                            "report": {
                                "created": True,
                                "job_id": [1],
                                "motivation": None,
                            },
                            "start_time": datetime.datetime(
                                2024, 10, 29, 10, 49, tzinfo=datetime.timezone.utc
                            ),
                            "status": "SUCCESS",
                        },
                    },
                ],
            )

        self.assertEqual(
            LastElasticReportUpdate.objects.get().last_update_datetime,
            datetime.datetime(2024, 10, 29, 11, tzinfo=datetime.UTC),
        )