from django.utils.timezone import now

from api_app.data_model_manager.models import IETFReport, IPDataModel
from tests import CustomTestCase


class BaseDataModelQuerySetTestCase(CustomTestCase):
    def test_merge(self):
        report1 = IETFReport.objects.create(
            rrname="test",
            rrtype="test2",
            rdata=["test3"],
            time_first=now(),
            time_last=now(),
        )
        report2 = IETFReport.objects.create(
            rrname="test4",
            rrtype="test5",
            rdata=["test6"],
            time_first=now(),
            time_last=now(),
        )
        ip = IPDataModel.objects.create(asn=3)
        ip2 = IPDataModel.objects.create(asn=4, resolutions=["2.2.2.2"])
        ip2.ietf_report.add(report2)
        ip3 = IPDataModel.objects.create(asn_rank=4, resolutions=["1.1.1.1"])
        ip3.ietf_report.add(report1)
        result = IPDataModel.objects.filter(pk__in=[ip.pk, ip2.pk, ip3.pk]).merge()

        self.assertEqual(ip2.asn, result.asn)
        self.assertEqual(ip3.asn_rank, result.asn_rank)
        self.assertCountEqual(ip2.resolutions + ip3.resolutions, result.resolutions)
        self.assertCountEqual(result.ietf_report.values_list("pk", flat=True), [report1.pk, report2.pk])
        report1.delete()
        report2.delete()
        ip.delete()
        ip2.delete()
        ip3.delete()
