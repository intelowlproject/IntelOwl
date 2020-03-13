import hashlib
import logging
import os

from django.test import TestCase
from unittest import skipIf

from api_app.script_analyzers.observable_analyzers import abuseipdb, shodan, fortiguard, maxmind, greynoise, googlesf, otx, \
    talos, tor, circl_pssl, circl_pdns, robtex_ip, robtex_fdns, robtex_rdns, vt2_get, ha_get, vt3_get, misp, dnsdb,\
    honeydb_twitter_scan, hunter

from api_app.models import Job
from intel_owl import settings

logger = logging.getLogger(__name__)
# disable logging library for travis
if settings.TRAVIS_TEST:
    logging.disable(logging.CRITICAL)


class IPAnalyzersTests(TestCase):

    def setUp(self):
        params = {
            "source": "test",
            "is_sample": False,
            "observable_name": os.environ.get("TEST_IP", "8.8.8.8"),
            "observable_classification": "ip",
            "force_privacy": False,
            "analyzers_requested": ["test"]
        }
        params["md5"] = hashlib.md5(params['observable_name'].encode('utf-8')).hexdigest()
        test_job = Job(**params)
        test_job.save()
        self.job_id = test_job.id
        self.observable_name = test_job.observable_name
        self.observable_classification = test_job.observable_classification

    def test_abuseipdb(self):
        report = abuseipdb.run("AbuseIPDB", self.job_id, self.observable_name, self.observable_classification, {})
        self.assertEqual(report.get('success', False), True)

    def test_shodan(self):
        report = shodan.run("Shodan", self.job_id, self.observable_name, self.observable_classification, {})
        self.assertEqual(report.get('success', False), True)

    def test_honeydb(self):
        report = honeydb_twitter_scan.run("HoneyDB", self.job_id, self.observable_name, self.observable_classification,
                                          {})
        self.assertEqual(report.get('success', False), True)

    def test_maxmind(self):
        report = maxmind.run("MaxMindDB", self.job_id, self.observable_name, self.observable_classification, {})
        self.assertEqual(report.get('success', False), True)

    def test_greynoise(self):
        report = greynoise.run("Greynoise", self.job_id, self.observable_name, self.observable_classification, {})
        self.assertEqual(report.get('success', False), True)

    def test_gsf(self):
        report = googlesf.run("GoogleSafeBrowsing", self.job_id, self.observable_name, self.observable_classification,
                              {})
        self.assertEqual(report.get('success', False), True)

    def test_otx(self):
        report = otx.run("OTX", self.job_id, self.observable_name, self.observable_classification, {})
        self.assertEqual(report.get('success', False), True)

    def test_talos(self):
        report = talos.run("TalosReputation", self.job_id, self.observable_name, self.observable_classification, {})
        self.assertEqual(report.get('success', False), True)

    def test_tor(self):
        report = tor.run("TorProject", self.job_id, self.observable_name, self.observable_classification, {})
        self.assertEqual(report.get('success', False), True)

    def test_circl_pssl(self):
        report = circl_pssl.run("CIRCL_PSSL", self.job_id, self.observable_name, self.observable_classification, {})
        self.assertEqual(report.get('success', False), True)

    def test_robtex_ip(self):
        report = robtex_ip.run("Robtex_IP", self.job_id, self.observable_name, self.observable_classification, {})
        self.assertEqual(report.get('success', False), True)

    def test_robtex_rdns(self):
        report = robtex_rdns.run("Robtex_RDNS", self.job_id, self.observable_name, self.observable_classification, {})
        self.assertEqual(report.get('success', False), True)

    @skipIf(settings.TRAVIS_TEST, "dnsdb account missing")
    def test_dnsdb(self):
        report = dnsdb.run("DNSDB", self.job_id, self.observable_name, self.observable_classification, {})
        self.assertEqual(report.get('success', False), True)

    def test_vt_get(self):
        report = vt2_get.run("VT_v2_Get", self.job_id, self.observable_name, self.observable_classification, {})
        self.assertEqual(report.get('success', False), True)

    def test_ha_get(self):
        report = ha_get.run("HA_Get", self.job_id, self.observable_name, self.observable_classification, {})
        self.assertEqual(report.get('success', False), True)

    def test_vt3_get(self):
        report = vt3_get.run("VT_v3_Get", self.job_id, self.observable_name, self.observable_classification, {})
        self.assertEqual(report.get('success', False), True)

    def test_misp_first(self):
        report = misp.run("MISP_FIRST", self.job_id, self.observable_name, self.observable_classification,
                          {'api_key_name': "FIRST_MISP_API", "url_key_name": "FIRST_MISP_URL"})
        self.assertEqual(report.get('success', False), True)


class DomainAnalyzersTests(TestCase):

    def setUp(self):
        params = {
            "source": "test",
            "is_sample": False,
            "observable_name": os.environ.get("TEST_DOMAIN", "www.google.com"),
            "observable_classification": "domain",
            "force_privacy": False,
            "analyzers_requested": ["test"]
        }
        params["md5"] = hashlib.md5(params['observable_name'].encode('utf-8')).hexdigest()
        test_job = Job(**params)
        test_job.save()
        self.job_id = test_job.id
        self.observable_name = test_job.observable_name
        self.observable_classification = test_job.observable_classification

    def test_fortiguard(self):
        report = fortiguard.run("Fortiguard", self.job_id, self.observable_name, self.observable_classification, {})
        self.assertEqual(report.get('success', False), True)

    def test_hunter(self):
        report = hunter.run("Hunter", self.job_id, self.observable_name, self.observable_classification, {})
        self.assertEqual(report.get('success', False), True)

    def test_gsf(self):
        report = googlesf.run("GoogleSafeBrowsing", self.job_id, self.observable_name, self.observable_classification, {})
        self.assertEqual(report.get('success', False), True)

    def test_otx(self):
        report = otx.run("OTX", self.job_id, self.observable_name, self.observable_classification, {})
        self.assertEqual(report.get('success', False), True)

    def test_circl_pdns(self):
        report = circl_pdns.run("CIRCL_PDNS", self.job_id, self.observable_name, self.observable_classification, {})
        self.assertEqual(report.get('success', False), True)

    def test_robtex_fdns(self):
        report = robtex_fdns.run("Robtex_FDNS", self.job_id, self.observable_name, self.observable_classification, {})
        self.assertEqual(report.get('success', False), True)

    @skipIf(settings.TRAVIS_TEST, "dnsdb account missing")
    def test_dnsdb(self):
        report = dnsdb.run("DNSDB", self.job_id, self.observable_name, self.observable_classification, {})
        self.assertEqual(report.get('success', False), True)

    def test_vt_get(self):
        report = vt2_get.run("VT_v2_Get", self.job_id, self.observable_name, self.observable_classification, {})
        self.assertEqual(report.get('success', False), True)

    def test_ha_get(self):
        report = ha_get.run("HA_Get", self.job_id, self.observable_name, self.observable_classification, {})
        self.assertEqual(report.get('success', False), True)

    def test_vt3_get(self):
        report = vt3_get.run("VT_v3_Get", self.job_id, self.observable_name, self.observable_classification, {})
        self.assertEqual(report.get('success', False), True)

    def test_misp_first(self):
        report = misp.run("MISP_FIRST", self.job_id, self.observable_name, self.observable_classification,
                          {'api_key_name': "FIRST_MISP_API", "url_key_name": "FIRST_MISP_URL"})
        self.assertEqual(report.get('success', False), True)


class URLAnalyzersTests(TestCase):

    def setUp(self):
        params = {
            "source": "test",
            "is_sample": False,
            "observable_name": os.environ.get("TEST_URL", "https://www.google.com/search?test"),
            "observable_classification": "url",
            "force_privacy": False,
            "analyzers_requested": ["test"]
        }
        params["md5"] = hashlib.md5(params['observable_name'].encode('utf-8')).hexdigest()
        test_job = Job(**params)
        test_job.save()
        self.job_id = test_job.id
        self.observable_name = test_job.observable_name
        self.observable_classification = test_job.observable_classification

    def test_fortiguard(self):
        report = fortiguard.run("Fortiguard", self.job_id, self.observable_name, self.observable_classification, {})
        self.assertEqual(report.get('success', False), True)

    def test_gsf(self):
        report = googlesf.run("GoogleSafeBrowsing", self.job_id, self.observable_name, self.observable_classification, {})
        self.assertEqual(report.get('success', False), True)

    def test_otx(self):
        report = otx.run("OTX", self.job_id, self.observable_name, self.observable_classification, {})
        self.assertEqual(report.get('success', False), True)

    def test_circl_pdns(self):
        report = circl_pdns.run("CIRCL_PDNS", self.job_id, self.observable_name, self.observable_classification, {})
        self.assertEqual(report.get('success', False), True)

    def test_robtex_fdns(self):
        report = robtex_fdns.run("Robtex_FDNS", self.job_id, self.observable_name, self.observable_classification, {})
        self.assertEqual(report.get('success', False), True)

    def test_vt_get(self):
        report = vt2_get.run("VT_v2_Get", self.job_id, self.observable_name, self.observable_classification, {})
        self.assertEqual(report.get('success', False), True)

    def test_vt3_get(self):
        report = vt3_get.run("VT_v3_Get", self.job_id, self.observable_name, self.observable_classification, {})
        self.assertEqual(report.get('success', False), True)


class HashAnalyzersTests(TestCase):

    def setUp(self):
        params = {
            "source": "test",
            "is_sample": False,
            "observable_name": os.environ.get("TEST_MD5", "446c5fbb11b9ce058450555c1c27153c"),
            "observable_classification": "hash",
            "force_privacy": False,
            "analyzers_requested": ["test"]
        }
        params["md5"] = hashlib.md5(params['observable_name'].encode('utf-8')).hexdigest()
        test_job = Job(**params)
        test_job.save()
        self.job_id = test_job.id
        self.observable_name = test_job.observable_name
        self.observable_classification = test_job.observable_classification

    def test_otx(self):
        report = otx.run("OTX", self.job_id, self.observable_name, self.observable_classification, {})
        self.assertEqual(report.get('success', False), True)

    def test_vt_get(self):
        report = vt2_get.run("VT_v2_Get", self.job_id, self.observable_name, self.observable_classification, {})
        self.assertEqual(report.get('success', False), True)

    def test_ha_get(self):
        report = ha_get.run("HA_Get", self.job_id, self.observable_name, self.observable_classification, {})
        self.assertEqual(report.get('success', False), True)

    def test_vt3_get(self):
        report = vt3_get.run("VT_v3_Get", self.job_id, self.observable_name, self.observable_classification, {})
        self.assertEqual(report.get('success', False), True)

    def test_misp_first(self):
        report = misp.run("MISP_FIRST", self.job_id, self.observable_name, self.observable_classification,
                          {'api_key_name': "FIRST_MISP_API", "url_key_name": "FIRST_MISP_URL"})
        self.assertEqual(report.get('success', False), True)
