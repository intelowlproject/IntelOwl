# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.


from kombu import uuid

from api_app.analyzers_manager.models import AnalyzerConfig, AnalyzerReport
from api_app.models import Job
from api_app.visualizers_manager.classes import (
    VisualizableBase,
    VisualizableBool,
    VisualizableHorizontalList,
    VisualizableLevel,
    VisualizableObject,
    VisualizableTitle,
    VisualizableVerticalList,
    Visualizer,
)
from api_app.visualizers_manager.enums import VisualizableColor
from api_app.visualizers_manager.models import VisualizerConfig
from tests import CustomTestCase


class VisualizableObjectTestCase(CustomTestCase):
    class MockUpVisualizableObject(VisualizableObject):
        @property
        def type(self):
            return "test"

    def test_to_dict(self):
        vo = self.MockUpVisualizableObject(True, False)
        result = vo.to_dict()

        expected_result = {
            "hide_if_empty": True,
            "disable_if_empty": False,
            "type": "test",
        }
        self.assertEqual(expected_result, result)


class VisualizableBaseTestCase(CustomTestCase):
    def test_to_dict(self):
        vo = VisualizableBase(
            "test",
            color=VisualizableColor.DARK,
            link="https://test.com",
            classname="test",
            hide_if_empty=True,
            disable_if_empty=True,
        )
        expected_result = {
            "hide_if_empty": True,
            "disable_if_empty": True,
            "type": "base",
            "value": "test",
            "color": "dark",
            "link": "https://test.com",
            "classname": "test",
            "icon": "",
        }
        self.assertEqual(vo.to_dict(), expected_result)


class VisualizableBoolTestCase(CustomTestCase):
    def test_to_dict(self):
        vo = VisualizableBool(name="test", value=True)
        expected_result = {
            "type": "bool",
            "name": "test",
            "value": True,
            "pill": True,
            "link": "",
            "classname": "",
            "color": "danger",
            "hide_if_empty": False,
            "disable_if_empty": True,
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
            "type": "title",
            "title": title.to_dict(),
            "value": value.to_dict(),
            "hide_if_empty": False,
            "disable_if_empty": True,
        }
        self.assertEqual(vo.to_dict(), expected_result)


class VisualizableVerticalListTestCase(CustomTestCase):
    def test_to_dict(self):
        value = VisualizableBase(
            value="test_value", color=VisualizableColor.DANGER, link="http://test_value"
        )
        vvl = VisualizableVerticalList(name="test", value=[value])
        expected_result = {
            "type": "vertical_list",
            "name": "test",
            "icon": "",
            "link": "",
            "classname": "",
            "color": "",
            "open": False,
            "hide_if_empty": False,
            "disable_if_empty": True,
            "values": [value.to_dict()],
        }
        self.assertEqual(vvl.to_dict()["values"], vvl.to_dict()["values"])
        self.assertNotEqual(0, len(vvl.to_dict()["values"]))
        self.assertEqual(vvl.to_dict(), expected_result)

    def test_to_dict_values_null(self):
        value = VisualizableBase(
            value="", color=VisualizableColor.DANGER, link="http://test_value"
        )
        vvl = VisualizableVerticalList(name="test", value=[value])
        expected_result = {
            "type": "vertical_list",
            "name": "test",
            "icon": "",
            "link": "",
            "color": "",
            "classname": "",
            "hide_if_empty": False,
            "disable_if_empty": True,
            "open": False,
            "values": [],
        }
        self.assertEqual(vvl.to_dict(), expected_result)

    def test_to_dict_values_empty(self):

        vvl = VisualizableVerticalList(name="test", value=[])
        expected_result = {
            "type": "vertical_list",
            "name": "test",
            "icon": "",
            "link": "",
            "color": "",
            "classname": "",
            "hide_if_empty": False,
            "disable_if_empty": True,
            "open": False,
            "values": [],
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
            "hide_if_empty": False,
            "disable_if_empty": True,
            "values": [value.to_dict()],
        }
        self.assertEqual(vvl.to_dict(), expected_result)

    def test_to_dict_values_null(self):
        vvl = VisualizableHorizontalList(value=[])
        expected_result = {
            "type": "horizontal_list",
            "hide_if_empty": False,
            "disable_if_empty": True,
            "values": [],
        }
        self.assertEqual(vvl.to_dict(), expected_result)

    def test_to_dict_values_empty(self):
        vvl = VisualizableHorizontalList(value=[])
        expected_result = {
            "type": "horizontal_list",
            "hide_if_empty": False,
            "disable_if_empty": True,
            "values": [],
        }
        self.assertEqual(vvl.to_dict(), expected_result)


class VisualizableLevelTestCase(CustomTestCase):
    def test_to_dict(self):
        value = VisualizableBase(
            value="test_value", color=VisualizableColor.DANGER, link="http://test_value"
        )
        vvl = VisualizableHorizontalList(value=[value])
        vl = VisualizableLevel()
        vl.add_level(level=0, horizontal_list=vvl)
        expected_result = {
            "level": 0,
            "elements": vvl.to_dict(),
        }
        self.assertEqual(vl.to_dict()[0], expected_result)


class VisualizerTestCase(CustomTestCase):
    fixtures = [
        "api_app/fixtures/0001_user.json",
        "api_app/fixtures/0002_analyzer_pluginconfig.json",
        "api_app/fixtures/0003_connector_pluginconfig.json",
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
        )

        subclasses = Visualizer.all_subclasses()
        for subclass in subclasses:
            print("\n" f"Testing Visualizer {subclass.__name__}")
            for config in VisualizerConfig.objects.filter(
                python_module=subclass.python_module
            ):
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
