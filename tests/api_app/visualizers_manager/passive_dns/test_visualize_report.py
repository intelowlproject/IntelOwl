from api_app.visualizers_manager.classes import (
    VisualizableBase,
    VisualizableVerticalList,
)
from api_app.visualizers_manager.visualizers.passive_dns.visualize_report import (
    visualize_report,
)
from tests import CustomTestCase


class TestVisualizeReport(CustomTestCase):
    def test_empty_report(self):
        report = {}
        visualizable_report = visualize_report(report)
        self.assertEqual({}, visualizable_report)

    def test_all_data_report(self):
        report = {
            "last_view": "2024-05-02",
            "first_view": "2024-04-05",
            "rrname": "test.com",
            "rrtype": "a",
            "rdata": "34.224.149.186",
            "count": 4477,
            "source": "CIRCLPassiveDNS",
            "source_description": "scan an observable against the CIRCL Passive DNS DB",  # noqa: E501
        }
        visualizable_report = visualize_report(report)
        print(visualizable_report)
        for _, ui_component in visualizable_report.items():
            self.assertTrue(isinstance(ui_component, VisualizableBase))

    def test_all_data_report_rdata_list(self):
        report = {
            "last_view": "2024-05-02",
            "first_view": "2024-04-05",
            "rrname": "test.com",
            "rrtype": "a",
            "rdata": ["34.224.149.186"],
            "count": 4477,
            "source": "CIRCLPassiveDNS",
            "source_description": "scan an observable against the CIRCL Passive DNS DB",  # noqa: E501
        }
        visualizable_report = visualize_report(report)
        print(visualizable_report)
        for key, ui_component in visualizable_report.items():
            if key == "rdata":
                self.assertTrue(isinstance(ui_component, VisualizableVerticalList))
            else:
                self.assertTrue(isinstance(ui_component, VisualizableBase))
