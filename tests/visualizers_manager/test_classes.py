from pathlib import PosixPath

from django.conf import settings
from kombu import uuid

from api_app.analyzers_manager.models import AnalyzerConfig, AnalyzerReport
from api_app.models import Job
from api_app.visualizers_manager.classes import Visualizer
from api_app.visualizers_manager.models import VisualizerConfig
from tests import CustomTestCase


class MockUpVisualizer(Visualizer):
    def run(self) -> dict:
        return {}


class VisualizerTestCase(CustomTestCase):
    fixtures = [
        "api_app/fixtures/0001_user.json",
    ]

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
