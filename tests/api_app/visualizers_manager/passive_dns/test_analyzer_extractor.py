import datetime

from kombu import uuid

from api_app.analyzables_manager.models import Analyzable
from api_app.analyzers_manager.models import AnalyzerConfig, AnalyzerReport
from api_app.choices import Classification
from api_app.models import Job
from api_app.visualizers_manager.visualizers.passive_dns.analyzer_extractor import (
    PDNSReport,
    extract_circlpdns_reports,
    extract_dnsdb_reports,
    extract_mnemonicpdns_reports,
    extract_otxquery_reports,
    extract_robtex_reports,
    extract_threatminer_reports,
    extract_validin_reports,
)
from tests import CustomTestCase


class TestOTXQuery(CustomTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.an = Analyzable.objects.create(
            name="195.22.26.248",
            classification=Classification.IP,
        )

        cls.job = Job.objects.create(
            user=cls.user,
            status=Job.STATUSES.RUNNING.value,
            analyzable=cls.an,
            received_request_time=datetime.datetime.now(),
        )
        cls.otx_report = None

    @classmethod
    def tearDownClass(cls) -> None:
        super().tearDownClass()
        cls.job.delete()
        if cls.otx_report:
            cls.otx_report.delete()
        cls.an.delete()

    def test_no_report(self):
        report = extract_otxquery_reports(AnalyzerReport.objects.filter(job=self.job), self.job)
        self.assertEqual([], report)

    def test_empty_report(self):
        self.otx_report = AnalyzerReport.objects.create(
            parameters={},
            report={},
            job=self.job,
            task_id=uuid(),
            config=AnalyzerConfig.objects.get(name="OTXQuery"),
        )
        report = extract_otxquery_reports(AnalyzerReport.objects.filter(job=self.job), self.job)
        self.assertEqual([], report)

    def test_all_data_report(self):
        self.otx_report = AnalyzerReport.objects.create(
            parameters={},
            report={
                "passive_dns": [
                    {
                        "address": "195.22.26.248",
                        "first": "2022-03-19T17:14:00",
                        "last": "2022-03-19T17:16:33",
                        "hostname": "4ed8a7c6.ard.rr.zealbino.com",
                        "record_type": "A",
                        "indicator_link": "/indicator/hostname/4ed8a7c6.ard.rr.zealbino.com",  # noqa: E501
                        "flag_url": "assets/images/flags/pt.png",
                        "flag_title": "Portugal",
                        "asset_type": "hostname",
                        "asn": "AS8426 claranet ltd",
                        "suspicious": False,
                        "whitelisted_message": [],
                        "whitelisted": False,
                    },
                ],
            },
            job=self.job,
            task_id=uuid(),
            config=AnalyzerConfig.objects.get(name="OTXQuery"),
        )
        report = extract_otxquery_reports(AnalyzerReport.objects.filter(job=self.job), self.job)
        self.assertEqual(
            [
                PDNSReport(
                    last_view="2022-03-19",
                    first_view="2022-03-19",
                    rrtype="A",
                    rdata="195.22.26.248",
                    rrname="4ed8a7c6.ard.rr.zealbino.com",
                    source="OTXQuery",
                    source_description="scan an observable on Alienvault OTX",
                ),
            ],
            report,
        )


class TestThreatminer(CustomTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.an = Analyzable.objects.create(
            name="test.com",
            classification=Classification.DOMAIN,
        )

        cls.job = Job.objects.create(
            user=cls.user,
            status=Job.STATUSES.RUNNING.value,
            analyzable=cls.an,
            received_request_time=datetime.datetime.now(),
        )
        cls.threatminer_report = None

    @classmethod
    def tearDownClass(cls) -> None:
        super().tearDownClass()
        cls.job.delete()
        if cls.threatminer_report:
            cls.threatminer_report.delete()
        cls.an.delete()

    def test_no_report(self):
        report = extract_threatminer_reports(AnalyzerReport.objects.filter(job=self.job), self.job)
        self.assertEqual([], report)

    def test_empty_report(self):
        self.threatminer_report = AnalyzerReport.objects.create(
            parameters={},
            report={},
            job=self.job,
            task_id=uuid(),
            config=AnalyzerConfig.objects.get(name="Threatminer"),
        )
        report = extract_threatminer_reports(AnalyzerReport.objects.filter(job=self.job), self.job)
        self.assertEqual([], report)

    def test_all_data_report(self):
        self.threatminer_report = AnalyzerReport.objects.create(
            parameters={},
            report={
                "results": [
                    {
                        "ip": "69.172.200.235",
                        "last_seen": "2019-12-03 21:28:00",
                        "first_seen": "2015-07-08 00:00:00",
                    },
                    {
                        "domain": "dns.google",
                        "last_seen": "2015-01-19 00:00:00",
                        "first_seen": "2015-01-19 00:00:00",
                    },
                ],
                "status_code": "200",
                "status_message": "Results found.",
            },
            job=self.job,
            task_id=uuid(),
            config=AnalyzerConfig.objects.get(name="Threatminer"),
        )
        report = extract_threatminer_reports(AnalyzerReport.objects.filter(job=self.job), self.job)
        self.assertEqual(
            [
                PDNSReport(
                    last_view="2019-12-03",
                    first_view="2015-07-08",
                    rrtype="A",
                    rdata="69.172.200.235",
                    rrname="test.com",
                    source="Threatminer",
                    source_description="retrieve data from [Threatminer API](https://www.threatminer.org/api.php)",  # noqa: E501
                ),
                PDNSReport(
                    last_view="2015-01-19",
                    first_view="2015-01-19",
                    rrtype="A",
                    rdata="dns.google",
                    rrname="test.com",
                    source="Threatminer",
                    source_description="retrieve data from [Threatminer API](https://www.threatminer.org/api.php)",  # noqa: E501
                ),
            ],
            report,
        )


class TestValidin(CustomTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.an = Analyzable.objects.create(
            name="test.com",
            classification=Classification.DOMAIN,
        )

        cls.job = Job.objects.create(
            user=cls.user,
            status=Job.STATUSES.RUNNING.value,
            analyzable=cls.an,
            received_request_time=datetime.datetime.now(),
        )
        cls.validin_report = None

    @classmethod
    def tearDownClass(cls) -> None:
        super().tearDownClass()
        cls.job.delete()
        if cls.validin_report:
            cls.validin_report.delete()
        cls.an.delete()

    def test_no_report(self):
        report = extract_validin_reports(AnalyzerReport.objects.filter(job=self.job), self.job)
        self.assertEqual([], report)

    def test_empty_report(self):
        self.validin_report = AnalyzerReport.objects.create(
            parameters={},
            report={},
            job=self.job,
            task_id=uuid(),
            config=AnalyzerConfig.objects.get(name="Validin"),
        )
        report = extract_validin_reports(AnalyzerReport.objects.filter(job=self.job), self.job)
        self.assertEqual([], report)

    def test_all_data_report(self):
        self.validin_report = AnalyzerReport.objects.create(
            parameters={},
            report={
                "status": "finished",
                "limited": False,
                "records": {
                    "A": [
                        {
                            "key": "test.com",
                            "value": "3.18.255.247",
                            "last_seen": 1718668800,
                            "first_seen": 1709402400,
                            "value_type": "IP4",
                        },
                        {
                            "key": "test.com",
                            "value": "34.224.149.186",
                            "last_seen": 1718668800,
                            "first_seen": 1709402400,
                            "value_type": "IP4",
                        },
                    ]
                },
                "query_key": "test.com",
                "query_opts": {
                    "type": "dom",
                    "limit": 250,
                    "parent": False,
                    "timeout": 30,
                    "wildcard": False,
                    "date_points": False,
                    "categories_include": ["A"],
                },
                "records_returned": 2,
            },
            job=self.job,
            task_id=uuid(),
            config=AnalyzerConfig.objects.get(name="Validin"),
        )
        report = extract_validin_reports(AnalyzerReport.objects.filter(job=self.job), self.job)

        self.assertEqual(
            [
                PDNSReport(
                    last_view="2024-06-18",
                    first_view="2024-03-02",
                    rrtype="A",
                    rdata="3.18.255.247",
                    rrname="test.com",
                    source="Validin",
                    source_description="[Validin's](https://app.validin.com) API for threat researchers, teams, and companies to investigate historic and current data describing the structure and composition of the internet.",  # noqa: E501
                ),
                PDNSReport(
                    last_view="2024-06-18",
                    first_view="2024-03-02",
                    rrtype="A",
                    rdata="34.224.149.186",
                    rrname="test.com",
                    source="Validin",
                    source_description="[Validin's](https://app.validin.com) API for threat researchers, teams, and companies to investigate historic and current data describing the structure and composition of the internet.",  # noqa: E501
                ),
            ],
            report,
        )


class TestDNSdb(CustomTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.an = Analyzable.objects.create(
            name="www.farsightsecurity.com",
            classification=Classification.DOMAIN,
        )

        cls.job = Job.objects.create(
            user=cls.user,
            status=Job.STATUSES.RUNNING.value,
            analyzable=cls.an,
            received_request_time=datetime.datetime.now(),
        )
        cls.dnsdb_report = None

    @classmethod
    def tearDownClass(cls) -> None:
        super().tearDownClass()
        cls.job.delete()
        if cls.dnsdb_report:
            cls.dnsdb_report.delete()
        cls.an.delete()

    def test_no_report(self):
        report = extract_dnsdb_reports(AnalyzerReport.objects.filter(job=self.job), self.job)
        self.assertEqual([], report)

    def test_empty_report(self):
        self.dnsdb_report = AnalyzerReport.objects.create(
            parameters={},
            report={},
            job=self.job,
            task_id=uuid(),
            config=AnalyzerConfig.objects.get(name="DNSDB"),
        )
        report = extract_dnsdb_reports(AnalyzerReport.objects.filter(job=self.job), self.job)
        self.assertEqual([], report)

    def test_all_data_report(self):
        self.dnsdb_report = AnalyzerReport.objects.create(
            parameters={},
            report={
                "data": [
                    {
                        "count": 5059,
                        "time_first": 1380139330,
                        "time_last": 1427881899,
                        "rrname": "www.farsightsecurity.com.",
                        "rrtype": "A",
                        "bailiwick": "farsightsecurity.com.",
                        "rdata": ["66.160.140.81"],
                    },
                ]
            },
            job=self.job,
            task_id=uuid(),
            config=AnalyzerConfig.objects.get(name="DNSDB"),
        )
        report = extract_dnsdb_reports(AnalyzerReport.objects.filter(job=self.job), self.job)
        self.assertEqual(
            [
                PDNSReport(
                    last_view="2015-04-01",
                    first_view="2013-09-25",
                    rrtype="A",
                    rdata=["66.160.140.81"],
                    rrname="www.farsightsecurity.com.",
                    source="DNSDB",
                    source_description="Scan an observable against the Passive DNS Farsight Database (support both v1 and v2 versions). Official [API docs](https://docs.dnsdb.info/dnsdb-apiv2/).",  # noqa: E501
                ),
            ],
            report,
        )


class TestRobtex(CustomTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.an = Analyzable.objects.create(
            name="test.com",
            classification=Classification.DOMAIN,
        )

        cls.job = Job.objects.create(
            user=cls.user,
            status=Job.STATUSES.RUNNING.value,
            analyzable=cls.an,
            received_request_time=datetime.datetime.now(),
        )
        cls.robtex_report = None

    @classmethod
    def tearDownClass(cls) -> None:
        super().tearDownClass()
        cls.job.delete()
        if cls.robtex_report:
            cls.robtex_report.delete()
        cls.an.delete()

    def test_no_report(self):
        report = extract_robtex_reports(AnalyzerReport.objects.filter(job=self.job), self.job)
        self.assertEqual([], report)

    def test_empty_report(self):
        self.robtex_report = AnalyzerReport.objects.create(
            parameters={},
            report=[],
            job=self.job,
            task_id=uuid(),
            config=AnalyzerConfig.objects.get(name="Robtex"),
        )
        report = extract_robtex_reports(AnalyzerReport.objects.filter(job=self.job), self.job)
        self.assertEqual([], report)

    def test_all_data_report(self):
        self.robtex_report = AnalyzerReport.objects.create(
            parameters={},
            report=[
                {
                    "count": 2,
                    "rrdata": "mx.spamexperts.com",
                    "rrname": "test.com",
                    "rrtype": "MX",
                    "time_last": 1582215078,
                    "time_first": 1441363932,
                }
            ],
            job=self.job,
            task_id=uuid(),
            config=AnalyzerConfig.objects.get(name="Robtex"),
        )
        report = extract_robtex_reports(AnalyzerReport.objects.filter(job=self.job), self.job)
        self.assertEqual(
            [
                PDNSReport(
                    last_view="2020-02-20",
                    first_view="2015-09-04",
                    rrtype="MX",
                    rdata="mx.spamexperts.com",
                    rrname="test.com",
                    source="Robtex",
                    source_description="scan a domain/IP against the Robtex Passive DNS DB",  # noqa: E501
                ),
            ],
            report,
        )


class TestMnemonicPDNS(CustomTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.an = Analyzable.objects.create(
            name="test.com",
            classification=Classification.DOMAIN,
        )

        cls.job = Job.objects.create(
            user=cls.user,
            status=Job.STATUSES.RUNNING.value,
            analyzable=cls.an,
            received_request_time=datetime.datetime.now(),
        )
        cls.mnemonicpdns_report = None

    @classmethod
    def tearDownClass(cls) -> None:
        super().tearDownClass()
        cls.job.delete()
        if cls.mnemonicpdns_report:
            cls.mnemonicpdns_report.delete()
        cls.an.delete()

    def test_no_report(self):
        report = extract_mnemonicpdns_reports(AnalyzerReport.objects.filter(job=self.job), self.job)
        self.assertEqual([], report)

    def test_empty_report(self):
        self.mnemonicpdns_report = AnalyzerReport.objects.create(
            parameters={},
            report=[],
            job=self.job,
            task_id=uuid(),
            config=AnalyzerConfig.objects.get(name="Mnemonic_PassiveDNS"),
        )
        report = extract_mnemonicpdns_reports(AnalyzerReport.objects.filter(job=self.job), self.job)
        self.assertEqual([], report)

    def test_all_data_report(self):
        self.mnemonicpdns_report = AnalyzerReport.objects.create(
            parameters={},
            report=[
                {
                    "count": 4477,
                    "rdata": "34.224.149.186",
                    "rrname": "test.com",
                    "rrtype": "a",
                    "time_last": 1714654257,
                    "time_first": 1712319486,
                }
            ],
            job=self.job,
            task_id=uuid(),
            config=AnalyzerConfig.objects.get(name="Mnemonic_PassiveDNS"),
        )
        report = extract_mnemonicpdns_reports(AnalyzerReport.objects.filter(job=self.job), self.job)
        self.assertEqual(
            [
                PDNSReport(
                    last_view="2024-05-02",
                    first_view="2024-04-05",
                    rrtype="a",
                    rdata="34.224.149.186",
                    rrname="test.com",
                    source="Mnemonic PassiveDNS",
                    source_description="Look up a domain or IP using the [Mnemonic PassiveDNS public API](https://docs.mnemonic.no/display/public/API/Passive+DNS+Overview).",  # noqa: E501
                ),
            ],
            report,
        )


class TestCIRCLPassiveDNS(CustomTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.an = Analyzable.objects.create(
            name="test.com",
            classification=Classification.DOMAIN,
        )

        cls.job = Job.objects.create(
            user=cls.user,
            status=Job.STATUSES.RUNNING.value,
            analyzable=cls.an,
            received_request_time=datetime.datetime.now(),
        )
        cls.circlpdns_report = None

    @classmethod
    def tearDownClass(cls) -> None:
        super().tearDownClass()
        cls.job.delete()
        if cls.circlpdns_report:
            cls.circlpdns_report.delete()
        cls.an.delete()

    def test_no_report(self):
        report = extract_circlpdns_reports(AnalyzerReport.objects.filter(job=self.job), self.job)
        self.assertEqual([], report)

    def test_empty_report(self):
        self.circlpdns_report = AnalyzerReport.objects.create(
            parameters={},
            report=[],
            job=self.job,
            task_id=uuid(),
            config=AnalyzerConfig.objects.get(name="CIRCLPassiveDNS"),
        )
        report = extract_circlpdns_reports(AnalyzerReport.objects.filter(job=self.job), self.job)
        self.assertEqual([], report)

    def test_all_data_report(self):
        self.circlpdns_report = AnalyzerReport.objects.create(
            parameters={},
            report=[
                {
                    "count": 4477,
                    "rdata": "34.224.149.186",
                    "rrname": "test.com",
                    "rrtype": "a",
                    "time_last": 1714654257,
                    "time_first": 1712319486,
                }
            ],
            job=self.job,
            task_id=uuid(),
            config=AnalyzerConfig.objects.get(name="CIRCLPassiveDNS"),
        )
        report = extract_circlpdns_reports(AnalyzerReport.objects.filter(job=self.job), self.job)
        self.assertEqual(
            [
                PDNSReport(
                    last_view="2024-05-02",
                    first_view="2024-04-05",
                    rrtype="a",
                    rdata="34.224.149.186",
                    rrname="test.com",
                    source="CIRCLPassiveDNS",
                    source_description="scan an observable against the CIRCL Passive DNS DB",  # noqa: E501
                ),
            ],
            report,
        )
