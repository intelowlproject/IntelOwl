from pathlib import PosixPath

from django.conf import settings
from kombu import uuid

from api_app.analyzers_manager.models import AnalyzerConfig, AnalyzerReport
from api_app.models import Job
from api_app.visualizers_manager.classes import (
    VisualizableBase,
    VisualizableObject,
    VisualizableTitle,
    Visualizer,
)
from api_app.visualizers_manager.enums import Color
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
            color=Color.DARK,
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
        }
        self.assertEqual(vo.to_dict(), expected_result)


class VisualizableTitleTestCase(CustomTestCase):
    def test_to_dict(self):

        title = VisualizableBase(
            value="test_title", color=Color.DARK, link="http://test_title"
        )

        value = VisualizableBase(
            value="test_value", color=Color.DANGER, link="http://test_value"
        )

        vo = VisualizableTitle(title, value)

        expected_result = {
            "type": "title",
            "title": "test_title",
            "value": "test_value",
            "title_color": "dark",
            "title_link": "http://test_title",
            "title_classname": "",
            "value_color": "danger",
            "value_link": "http://test_value",
            "value_classname": "",
            "hide_if_empty": False,
            "disable_if_empty": True,
        }

        self.assertEqual(vo.to_dict(), expected_result)


class VisualizerTestCase(CustomTestCase):
    fixtures = [
        "api_app/fixtures/0001_user.json",
    ]

    class MockUpVisualizer(Visualizer):
        def run(self) -> dict:
            return {}

    def test_analyzer_reports(self):
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
        v = self.MockUpVisualizer(vc, job.pk, {}, uuid())
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
        num_visualizers = 0
        dir = PosixPath(str(settings.BASE_VISUALIZER_PYTHON_PATH).replace(".", "/"))
        for visualizer in dir.iterdir():
            if (
                visualizer.is_file()
                and visualizer.suffix == ".py"
                and visualizer.stem != "__init__"
            ):
                package = (
                    f"{str(visualizer.parent).replace('/', '.')}.{visualizer.stem}"
                )
                __import__(package)
                num_visualizers += 1
        subclasses = Visualizer.__subclasses__()
        self.assertEqual(num_visualizers, len(subclasses))
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
                except TimeoutError:
                    self.fail(
                        f"Visualizer {subclass.__name__}"
                        f" with config {config.name} "
                        f"went in timeout after {timeout_seconds}"
                    )
                finally:
                    from api_app.analyzers_manager.models import AnalyzerConfig
                    from api_app.connectors_manager.models import ConnectorConfig

                    signal.alarm(0)
                    AnalyzerConfig.objects.all().delete()
                    ConnectorConfig.objects.all().delete()
        job.delete()
