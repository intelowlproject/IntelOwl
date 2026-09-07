# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
import os

from django.conf import settings
from django.utils.timezone import now

from api_app.analyzables_manager.models import Analyzable
from api_app.analyzers_manager.file_analyzers import quark_engine, yara_scan
from api_app.analyzers_manager.observable_analyzers import (
    ja4_db,
    maxmind,
    phishing_army,
    talos,
    tor,
    tor_nodes_danmeuk,
    tweetfeeds,
)
from api_app.choices import Classification
from api_app.models import Job
from intel_owl.tasks import check_stuck_analysis, remove_old_jobs

from . import CustomTestCase, get_logger
from .mock_utils import MockUpResponse, if_mock_connections, patch, skip

logger = get_logger()


class CronTests(CustomTestCase):
    def test_check_stuck_analysis(self):
        import datetime

        an = Analyzable.objects.create(
            name="8.8.8.8",
            classification=Classification.IP,
        )
        _job = Job.objects.create(
            user=self.user,
            status=Job.STATUSES.RUNNING.value,
            analyzable=an,
            received_request_time=now(),
        )
        self.assertCountEqual(check_stuck_analysis(), [])

        _job.received_request_time = now() - datetime.timedelta(hours=1)
        _job.save()
        self.assertCountEqual(check_stuck_analysis(), [_job.pk])

        _job.status = Job.STATUSES.PENDING.value
        _job.save()
        self.assertCountEqual(check_stuck_analysis(check_pending=False), [])

        self.assertCountEqual(check_stuck_analysis(check_pending=True), [_job.pk])
        _job.status = Job.STATUSES.ANALYZERS_RUNNING.value
        _job.save()
        self.assertCountEqual(check_stuck_analysis(check_pending=False), [_job.pk])
        _job.delete()
        an.delete()

    def test_remove_old_jobs(self):
        import datetime

        an = Analyzable.objects.create(
            name="8.8.8.8",
            classification=Classification.IP,
        )

        _job = Job.objects.create(
            user=self.user,
            status=Job.STATUSES.FAILED.value,
            analyzable=an,
            received_request_time=now(),
            finished_analysis_time=now(),
        )
        self.assertEqual(remove_old_jobs(), 0)

        _job.finished_analysis_time = now() - datetime.timedelta(days=10)
        _job.save()
        an_pk = an.pk
        self.assertEqual(remove_old_jobs(), 1)
        # verify orphaned analyzable is also cleaned up
        self.assertFalse(Analyzable.objects.filter(pk=an_pk).exists())

    @if_mock_connections(skip("not working without connection"))
    def test_maxmind_updater(self):
        maxmind.Maxmind.update()
        for db in maxmind.Maxmind.get_db_names():
            self.assertTrue(os.path.exists(db))

    @if_mock_connections(patch("requests.get", return_value=MockUpResponse({}, 200, text="91.192.100.61")))
    def test_talos_updater(self, mock_get=None):
        db_file_path = talos.Talos.update()
        self.assertTrue(os.path.exists(db_file_path))

    @if_mock_connections(
        patch(
            "requests.get",
            return_value=MockUpResponse(
                {}, 200, content=b"# Phishing Army Blocklist\nexample.com\nevil-phishing.net\nbadsite.org\n"
            ),
        )
    )
    def test_phishing_army_updater(self, mock_get=None):
        from api_app.analyzers_manager.models import PhishingArmyDomain

        result = phishing_army.PhishingArmy.update()
        self.assertTrue(result)
        self.assertTrue(PhishingArmyDomain.objects.exists())

    @if_mock_connections(
        patch(
            "requests.get",
            return_value=MockUpResponse({}, 200, content=b"ExitAddress 93.95.230.253 2022-08-18 14:44:33"),
        )
    )
    def test_tor_updater(self, mock_get=None):
        from api_app.analyzers_manager.models import TorExitNode

        result = tor.Tor.update()
        self.assertTrue(result)
        self.assertTrue(TorExitNode.objects.exists())

    @if_mock_connections(
        patch(
            "requests.get",
            return_value=MockUpResponse({}, 200, content=b"100.10.37.131\n100.14.156.183\n45.141.119.113\n"),
        )
    )
    def test_tor_nodes_danmeuk_updater(self, mock_get=None):
        from api_app.analyzers_manager.models import TorDanMeUKNode

        result = tor_nodes_danmeuk.TorNodesDanMeUK.update()
        self.assertTrue(result)
        self.assertTrue(TorDanMeUKNode.objects.exists())

    @if_mock_connections(
        patch(
            "requests.get",
            return_value=MockUpResponse(
                [
                    {
                        "date": "2024-03-19 00:31:36",
                        "user": "Metemcyber",
                        "type": "url",
                        "value": "http://210.56.49.214",
                        "tags": ["#phishing"],
                    },
                    {
                        "date": "2024-03-19 00:31:36",
                        "user": "Metemcyber",
                        "type": "url",
                        "value": "https://www.bhafulp.cn",
                        "tags": ["#phishing"],
                    },
                ],
                200,
            ),
        ),
    )
    def test_tweetfeed_updater(self, mock_get=None):
        from api_app.analyzers_manager.models import TweetFeedItem

        result = tweetfeeds.TweetFeeds.update()
        self.assertTrue(result)
        self.assertTrue(TweetFeedItem.objects.exists())

    @if_mock_connections(
        patch(
            "requests.get",
            return_value=MockUpResponse(
                [
                    {
                        "application": "Nmap",
                        "library": None,
                        "device": None,
                        "os": None,
                        "user_agent_string": None,
                        "certificate_authority": None,
                        "observation_count": 1,
                        "verified": True,
                        "notes": "",
                        "ja4_fingerprint": None,
                        "ja4_fingerprint_string": None,
                        "ja4s_fingerprint": None,
                        "ja4h_fingerprint": None,
                        "ja4x_fingerprint": None,
                        "ja4t_fingerprint": "1024_2_1460_00",
                        "ja4ts_fingerprint": None,
                        "ja4tscan_fingerprint": None,
                    },
                    {
                        "application": None,
                        "library": None,
                        "device": None,
                        "os": None,
                        "user_agent_string": """Mozilla/5.0
                            (Windows NT 10.0; Win64; x64)
                            AppleWebKit/537.36 (KHTML, like Gecko)
                            Chrome/125.0.0.0
                            Safari/537.36""",
                        "certificate_authority": None,
                        "observation_count": 1,
                        "verified": False,
                        "notes": None,
                        "ja4_fingerprint": """t13d1517h2_
                            8daaf6152771_
                            b0da82dd1658""",
                        "ja4_fingerprint_string": """t13d1517h2_002f,0035,009c,
                            009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,
                            cca9_0005,000a,000b,000d,0012,0017,001b,0023,0029,002b,
                            002d,0033,4469,fe0d,ff01_0403,0804,0401,
                            0503,0805,0501,0806,0601""",
                        "ja4s_fingerprint": None,
                        "ja4h_fingerprint": """ge11cn20enus_
                            60ca1bd65281_
                            ac95b44401d9_
                            8df6a44f726c""",
                        "ja4x_fingerprint": None,
                        "ja4t_fingerprint": None,
                        "ja4ts_fingerprint": None,
                        "ja4tscan_fingerprint": None,
                    },
                ],
                200,
            ),
        )
    )
    def test_ja4_db_updater(self, mock_get=None):
        ja4_db.Ja4DB.update()
        from api_app.analyzers_manager.models import Ja4DBEntry

        self.assertTrue(Ja4DBEntry.objects.exists())

    def test_quark_updater(self):
        from quark.config import DIR_PATH

        quark_engine.QuarkEngine.update()
        self.assertTrue(os.path.exists(DIR_PATH))

    @if_mock_connections(
        patch("git.Repo"),
        patch("requests.get", return_value=MockUpResponse({}, 200)),
        patch("zipfile.ZipFile"),
    )
    def test_yara_updater(self, mock_zipfile=None, mock_get=None, mock_repo=None):
        if mock_zipfile is None or mock_get is None or mock_repo is None:
            yara_scan.YaraScan.update()
            self.assertTrue(os.path.isdir(settings.YARA_RULES_PATH))
        else:

            def create_yara_file(path):
                os.makedirs(path, exist_ok=True)
                yara_file = os.path.join(path, "test_rule.yar")
                with open(yara_file, "w", encoding="utf_8") as f:
                    f.write(
                        "rule TestRule {\n"
                        "    strings:\n"
                        '        $test = "test"\n'
                        "    condition:\n"
                        "        $test\n"
                        "}\n"
                    )

            mock_repo.clone_from.side_effect = lambda url, path, **kwargs: create_yara_file(path)
            mock_zipfile.return_value.extractall.side_effect = create_yara_file
            result = yara_scan.YaraScan.update()
            self.assertTrue(result)
