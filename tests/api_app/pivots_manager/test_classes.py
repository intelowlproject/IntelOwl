from api_app.pivots_manager.classes import Pivot
from api_app.pivots_manager.models import PivotConfig
from tests import CustomTestCase


class PivotTestCase(CustomTestCase):
    fixtures = [
        "api_app/fixtures/0001_user.json",
    ]

    def test_subclasses(self):
        def handler(signum, frame):
            raise TimeoutError("end of time")

        import signal

        signal.signal(signal.SIGALRM, handler)

        subclasses = Pivot.all_subclasses()
        for subclass in subclasses:
            print("\n" f"Testing Pivot {subclass.__name__}")
            configs = PivotConfig.objects.filter(python_module=subclass.python_module)
            for config in configs:
                timeout_seconds = config.soft_time_limit
                timeout_seconds = min(timeout_seconds, 20)
                print(
                    "\t"
                    f"Testing with config {config.name}"
                    f" for {timeout_seconds} seconds"
                )
                sub = subclass(config)
                signal.alarm(timeout_seconds)
                try:
                    sub.start(None, {}, None)
                except Exception as e:
                    self.fail(
                        f"Pivot {subclass.__name__}"
                        f" with config {config.name} "
                        f"failed {e}"
                    )
                finally:
                    signal.alarm(0)
