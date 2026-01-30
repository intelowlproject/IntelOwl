from kombu import uuid

from api_app.analyzables_manager.models import Analyzable
from api_app.choices import Classification
from api_app.models import Job
from api_app.pivots_manager.classes import Pivot
from api_app.pivots_manager.models import PivotConfig
from tests import CustomTestCase


class PivotTestCase(CustomTestCase):
    fixtures = [
        "api_app/fixtures/0001_user.json",
    ]

    def _create_jobs(self):
        an = Analyzable.objects.create(
            name="test.com",
            classification=Classification.DOMAIN,
        )

        Job.objects.create(
            user=self.superuser,
            status="reported_without_fails",
            analyzable=an,
        )

    def test_subclasses(self):
        def handler(signum, frame):
            raise TimeoutError("end of time")

        import signal

        signal.signal(signal.SIGALRM, handler)
        self._create_jobs()
        subclasses = Pivot.all_subclasses()
        for subclass in Pivot.all_subclasses():
            subclasses.extend(subclass.all_subclasses())
        for subclass in subclasses:
            print(f"\nTesting Pivot {subclass.__name__}")
            configs = PivotConfig.objects.filter(python_module=subclass.python_module)
            for config in configs:
                timeout_seconds = config.soft_time_limit
                timeout_seconds = min(timeout_seconds, 20)
                print(f"\tTesting with config {config.name} for {timeout_seconds} seconds")
                job = Job.objects.get(analyzable__classification="domain")
                sub = subclass(config)
                signal.alarm(timeout_seconds)
                try:
                    sub.start(job.pk, {}, uuid())
                except Exception as e:
                    self.fail(f"Pivot {subclass.__name__} with config {config.name} failed {e}")
                finally:
                    signal.alarm(0)
