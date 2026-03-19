import requests

from api_app.analyzers_manager.exceptions import AnalyzerRunException
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
            print(f"\nTesting Connector {subclass.__name__}")
            configs = IngestorConfig.objects.filter(python_module=subclass.python_module)
            if not configs.exists():
                self.fail(f"There is a python module {subclass.python_module} without any configuration")
            for config in configs:
                timeout_seconds = config.soft_time_limit
                timeout_seconds = min(timeout_seconds, 60)
                print(f"\tTesting with config {config.name} for {timeout_seconds} seconds")

                from api_app.models import PluginConfig

                for param in config.parameters.annotate_configured(config, config.user).filter(
                    required=True, configured=False
                ):
                    PluginConfig.objects.create(
                        parameter=param,
                        value="https://intelowl.com" if "url" in param.name else "test",
                        ingestor_config=config,
                        owner=config.user,
                    )

                sub = subclass(config)
                signal.alarm(timeout_seconds)
                try:
                    sub.start(None, {}, None)
                except (requests.exceptions.RequestException, AnalyzerRunException) as e:
                    self.skipTest(
                        f"Network error for {subclass.__name__} with config {config.name}, skipping: {e}"
                    )
                except Exception as e:
                    self.fail(f"Ingestor {subclass.__name__} with config {config.name} failed {e}")
                finally:
                    signal.alarm(0)
