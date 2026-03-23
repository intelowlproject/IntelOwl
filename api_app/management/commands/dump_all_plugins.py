from typing import Type

from django.db.migrations.autodetector import MigrationAutodetector

from api_app.analyzers_manager.models import AnalyzerConfig
from api_app.connectors_manager.models import ConnectorConfig
from api_app.ingestors_manager.models import IngestorConfig
from api_app.management.commands.dumpplugin import Command as DumpPluginCommand
from api_app.models import PythonConfig
from api_app.pivots_manager.models import PivotConfig
from api_app.playbooks_manager.models import PlaybookConfig
from api_app.visualizers_manager.models import VisualizerConfig


class Command(DumpPluginCommand):
    help = "Create migration file from all plugin in an application"

    @staticmethod
    def add_arguments(parser):
        parser.add_argument(
            "plugin_class",
            type=str,
            help="Plugin config class to use",
            choices=[
                AnalyzerConfig.__name__,
                ConnectorConfig.__name__,
                VisualizerConfig.__name__,
                IngestorConfig.__name__,
                PivotConfig.__name__,
                PlaybookConfig.__name__,
            ],
        )

    @property
    def migration_counter(self):
        try:
            self._migration_counter
        except AttributeError:
            self._migration_counter = 0
        return self._migration_counter

    @migration_counter.setter
    def migration_counter(self, value):
        self._migration_counter = value

    def _get_last_migration(self, app):
        if app == "api_app":
            return "0001_2_initial_squashed"
        else:
            if self.migration_counter == 0:
                if app == "pivots_manager":
                    return "0001_2_initial_squashed"
                else:
                    return "0001_initial_squashed"
            else:
                return self.name_file[:-3]

    def _name_file(self, obj, app):
        last_migration_number = MigrationAutodetector.parse_number(self._get_last_migration(app))
        if self.migration_counter == 0:
            last_migration_number += 1
        return (
            f"{str(int(last_migration_number)).rjust(4, '0')}"
            f"_{str(int(self.migration_counter)).rjust(4, '0')}"
            f"_{obj.snake_case_name}_{obj.name.lower()}.py"
        )

    def handle(self, *args, **options):
        config_class = options["plugin_class"]
        class_: Type[PythonConfig] = self.str_to_class[config_class]
        for name in class_.objects.values_list("name", flat=True):
            super().handle(plugin_name=name, plugin_class=config_class)
            self.migration_counter += 1
