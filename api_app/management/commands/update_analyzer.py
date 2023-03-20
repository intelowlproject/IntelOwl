"""This module contains functions and classes to inspect celery workers"""

from django.core.management import BaseCommand

from api_app.analyzers_manager.models import AnalyzerConfig


class Command(BaseCommand):
    help = "Execute celery task"

    def add_arguments(self, parser):
        parser.add_argument(
            "config_name",
            type=str,
            help="Analyzer config name to use",
        )

    def handle(self, *args, **options):
        try:
            analyzer_config = AnalyzerConfig.objects.get(name=options["config_name"])
        except AnalyzerConfig.DoesNotExist:
            self.stdout.write(
                self.style.WARNING(
                    f"Configuration {options['config_name']} does not exists"
                )
            )
            return
        if analyzer_config.is_runnable():
            class_ = analyzer_config.python_class
            if hasattr(class_, "_update") and callable(class_._update):
                self.stdout.write(
                    self.style.SUCCESS(f"Starting update of {analyzer_config.name}")
                )
                class_._update()
                self.stdout.write(
                    self.style.SUCCESS(f"Finished update of {analyzer_config.name}")
                )
            else:
                self.stdout.write(
                    self.style.WARNING(
                        f"Configuration {analyzer_config.name} "
                        "does not implement _update method"
                    )
                )
        else:
            self.stdout.write(
                self.style.WARNING(
                    f"Configuration {analyzer_config.name} is not runnable"
                )
            )
