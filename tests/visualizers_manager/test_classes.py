# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.


from kombu import uuid

from api_app.analyzers_manager.models import AnalyzerConfig, AnalyzerReport
from api_app.models import Job
from api_app.visualizers_manager.classes import (
    VisualizableBase,
    VisualizableBool,
    VisualizableHorizontalList,
    VisualizableObject,
    VisualizablePage,
    VisualizableTitle,
    VisualizableVerticalList,
    Visualizer,
)
from api_app.visualizers_manager.enums import VisualizableColor, VisualizableSize
from api_app.visualizers_manager.models import VisualizerConfig
from tests import CustomTestCase


class VisualizableObjectTestCase(CustomTestCase):
    class MockUpVisualizableObject(VisualizableObject):
        @property
        def type(self):
            return "test"

    def test_to_dict(self):
        vo = self.MockUpVisualizableObject(size=VisualizableSize.S_1, disable=False)
        result = vo.to_dict()

        expected_result = {
            "alignment": "around",
            "size": "1",
            "disable": False,
            "type": "test",
        }
        self.assertEqual(expected_result, result)


class VisualizableBaseTestCase(CustomTestCase):
    def test_to_dict(self):
        vo = VisualizableBase(
            "test",
            color=VisualizableColor.DARK,
            link="https://test.com",
            disable=True,
        )
        expected_result = {
            "alignment": "center",
            "disable": True,
            "bold": False,
            "italic": False,
            "type": "base",
            "value": "test",
            "color": "dark",
            "size": "auto",
            "link": "https://test.com",
            "icon": "",
        }
        self.assertEqual(vo.to_dict(), expected_result)

    def test_empty(self):
        vo = VisualizableBase(
            "",
            color=VisualizableColor.DARK,
            link="https://test.com",
            disable=False,
        )
        expected_result = {}
        self.assertEqual(vo.to_dict(), expected_result)

    def test_disable(self):
        vo = VisualizableBase(
            value="",
            color=VisualizableColor.DARK,
            size=VisualizableSize.S_3,
            link="https://test.com",
            disable=True,
        )
        expected_result = {
            "alignment": "center",
            "disable": True,
            "bold": False,
            "italic": False,
            "type": "base",
            "value": "",
            "color": "dark",
            "size": "3",
            "link": "https://test.com",
            "icon": "",
        }
        self.assertEqual(vo.to_dict(), expected_result)


class VisualizableBoolTestCase(CustomTestCase):
    def test_to_dict(self):
        vo = VisualizableBool(value="test", disable=False)
        expected_result = {
            "type": "bool",
            "value": "test",
            "link": "",
            "color": "danger",
            "icon": "",
            "italic": False,
            "size": "auto",
            "disable": False,
        }
        self.assertEqual(vo.to_dict(), expected_result)


class VisualizableTitleTestCase(CustomTestCase):
    def test_to_dict(self):

        title = VisualizableBase(
            value="test_title", color=VisualizableColor.DARK, link="http://test_title"
        )

        value = VisualizableBase(
            value="test_value", color=VisualizableColor.DANGER, link="http://test_value"
        )

        vo = VisualizableTitle(title, value)

        expected_result = {
            "alignment": "center",
            "type": "title",
            "title": title.to_dict(),
            "value": value.to_dict(),
            "size": "auto",
            "disable": True,
        }
        self.assertEqual(vo.to_dict(), expected_result)


class VisualizableVerticalListTestCase(CustomTestCase):
    def test_to_dict(self):
        name = VisualizableBase(value="test")
        value = VisualizableBase(
            value="test_value", color=VisualizableColor.DANGER, link="http://test_value"
        )
        vvl = VisualizableVerticalList(name=name, value=[value])
        expected_result = {
            "alignment": "center",
            "type": "vertical_list",
            "name": name.to_dict(),
            "open": False,
            "disable": True,
            "size": "auto",
            "values": [value.to_dict()],
        }
        self.assertEqual(vvl.to_dict()["values"], vvl.to_dict()["values"])
        self.assertNotEqual(0, len(vvl.to_dict()["values"]))
        self.assertEqual(vvl.to_dict(), expected_result)

    def test_to_dict_values_null(self):
        name = VisualizableBase(value="test")
        value = VisualizableBase(
            value="", color=VisualizableColor.DANGER, link="http://test_value"
        )
        vvl = VisualizableVerticalList(name=name, value=[value])
        expected_result = {
            "alignment": "center",
            "type": "vertical_list",
            "name": name.to_dict(),
            "disable": True,
            "open": False,
            "size": "auto",
            "values": [],
        }
        self.assertCountEqual(vvl.to_dict(), expected_result)

    def test_to_dict_values_empty(self):

        name = VisualizableBase(value="test")
        vvl = VisualizableVerticalList(name=name, value=[])
        expected_result = {
            "alignment": "center",
            "type": "vertical_list",
            "name": name.to_dict(),
            "disable": True,
            "open": False,
            "size": "auto",
            "values": [
                {
                    "alignment": "center",
                    "bold": False,
                    "color": "",
                    "disable": False,
                    "icon": "",
                    "italic": False,
                    "link": "",
                    "size": "auto",
                    "type": "base",
                    "value": "no data available",
                }
            ],
        }
        self.assertEqual(vvl.to_dict(), expected_result)


class VisualizableHorizontalListTestCase(CustomTestCase):
    def test_to_dict(self):
        value = VisualizableBase(
            value="test_value", color=VisualizableColor.DANGER, link="http://test_value"
        )
        vvl = VisualizableHorizontalList(value=[value])
        expected_result = {
            "type": "horizontal_list",
            "alignment": "around",
            "values": [value.to_dict()],
        }
        self.assertEqual(vvl.to_dict(), expected_result)

    def test_to_dict_values_null(self):
        vvl = VisualizableHorizontalList(value=[])
        expected_result = {
            "type": "horizontal_list",
            "alignment": "around",
            "values": [],
        }
        self.assertEqual(vvl.to_dict(), expected_result)

    def test_to_dict_values_empty(self):
        vvl = VisualizableHorizontalList(value=[])
        expected_result = {
            "type": "horizontal_list",
            "alignment": "around",
            "values": [],
        }
        self.assertEqual(vvl.to_dict(), expected_result)


class VisualizablePageTestCase(CustomTestCase):
    def test_to_dict(self):
        value = VisualizableBase(
            value="test_value", color=VisualizableColor.DANGER, link="http://test_value"
        )
        vvl = VisualizableHorizontalList(value=[value])
        vl = VisualizablePage()
        vl.add_level(level=0, horizontal_list=vvl)
        expected_result = {
            "level": 0,
            "elements": vvl.to_dict(),
        }
        self.assertEqual(vl.to_dict()[1][0], expected_result)


class VisualizerTestCase(CustomTestCase):
    fixtures = [
        "api_app/fixtures/0001_user.json",
    ]

    def test_analyzer_reports(self):
        class MockUpVisualizer(Visualizer):
            def run(self) -> dict:
                return {}

        ac = AnalyzerConfig.objects.first()
        job = Job.objects.create(
            observable_name="test.com",
            observable_classification="domain",
            status="reported_without_fails",
        )
        vc = VisualizerConfig.objects.create(
            name="test", python_module="yara.Yara", description="test"
        )
        vc.analyzers.set([ac])
        ar = AnalyzerReport.objects.create(config=ac, job=job, task_id=uuid())
        v = MockUpVisualizer(vc, job.pk, {}, uuid())
        self.assertEqual(list(v.analyzer_reports()), [ar])
        ar.delete()
        job.delete()
        vc.delete()

    def test_subclasses(self):
        def handler(signum, frame):
            raise TimeoutError("end of time")

        import signal

        signal.signal(signal.SIGALRM, handler)

        job = Job.objects.create(
            observable_name="test.com",
            observable_classification="domain",
            status="reported_without_fails",
            user=self.superuser,
        )

        subclasses = Visualizer.all_subclasses()
        for subclass in subclasses:
            print("\n" f"Testing Visualizer {subclass.__name__}")
            for config in VisualizerConfig.objects.filter(
                python_module=subclass.python_module
            ):
                job.visualizers_to_execute.set([config])
                timeout_seconds = config.soft_time_limit
                timeout_seconds = min(timeout_seconds, 20)
                print(
                    "\t"
                    f"Testing with config {config.name}"
                    f" for {timeout_seconds} seconds"
                )
                sub = subclass(config, job.pk, {}, uuid())
                signal.alarm(timeout_seconds)
                try:
                    sub.start()
                except Exception as e:
                    self.fail(
                        f"Visualizer {subclass.__name__}"
                        f" with config {config.name} "
                        f"failed {e}"
                    )
                finally:
                    signal.alarm(0)

        job.delete()
