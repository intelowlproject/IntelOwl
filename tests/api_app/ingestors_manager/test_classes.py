from api_app.ingestors_manager.classes import Ingestor
from api_app.ingestors_manager.models import IngestorConfig
from tests import CustomTestCase


class IngestorTestCase(CustomTestCase):
    fixtures = [
        "api_app/fixtures/0001_user.json",
    ]

    def test_subclasses(self):
        def handler(signum, frame):
            raise TimeoutError("end of time")

        import signal

        signal.signal(signal.SIGALRM, handler)

        subclasses = Ingestor.all_subclasses()
        for subclass in subclasses:
            print("\n" f"Testing Connector {subclass.__name__}")
            configs = IngestorConfig.objects.filter(
                python_module=subclass.python_module
            )
            if not configs.exists():
                self.fail(
                    f"There is a python module {subclass.python_module} "
                    "without any configuration"
                )
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
                        f"Ingestor {subclass.__name__}"
                        f" with config {config.name} "
                        f"failed {e}"
                    )
                finally:
                    signal.alarm(0)
