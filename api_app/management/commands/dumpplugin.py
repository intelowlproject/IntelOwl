# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
import json
from pathlib import PosixPath

from django.core.management import BaseCommand

from api_app.analyzers_manager.models import AnalyzerConfig
from api_app.analyzers_manager.serializers import AnalyzerConfigSerializerForMigration
from api_app.connectors_manager.models import ConnectorConfig
from api_app.connectors_manager.serializers import ConnectorConfigSerializerForMigration
from api_app.ingestors_manager.models import IngestorConfig
from api_app.ingestors_manager.serializers import IngestorConfigSerializerForMigration
from api_app.models import PluginConfig
from api_app.pivots_manager.models import PivotConfig
from api_app.pivots_manager.serializers import PivotConfigSerializerForMigration
from api_app.serializers import (
    ParameterCompleteSerializer,
    PluginConfigCompleteSerializer,
)
from api_app.visualizers_manager.models import VisualizerConfig
from api_app.visualizers_manager.serializers import (
    VisualizerConfigSerializerForMigration,
)


class Command(BaseCommand):
    help = "Create migration file from plugin saved inside the db"

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
            ],
        )
        parser.add_argument(
            "plugin_name",
            type=str,
            help="Plugin config name to use",
        )

    @staticmethod
    def _get_serialization(obj, serializer_class):
        obj_data = serializer_class(obj).data
        obj_data["model"] = f"{obj._meta.app_label}.{obj._meta.object_name}"
        params_data = []
        values_data = []
        for parameter in obj.parameters.all():
            params_data.append(ParameterCompleteSerializer(parameter).data)
            try:
                # default value
                value = PluginConfig.objects.get(
                    owner=None,
                    for_organization=False,
                    parameter=parameter,
                    parameter__is_secret=False,
                )
            except PluginConfig.DoesNotExist:
                ...
            else:
                values_data.append(PluginConfigCompleteSerializer(value).data)
        return obj_data, params_data, values_data

    @staticmethod
    def _imports() -> str:
        return """from django.db import migrations
from django.db.models.fields.related_descriptors import (
    ForwardManyToOneDescriptor,
    ForwardOneToOneDescriptor,
    ManyToManyDescriptor,
)
"""

    @staticmethod
    def _migrate_template():
        return """
def _get_real_obj(Model, field, value):
    if type(getattr(Model, field)) in [ForwardManyToOneDescriptor, ForwardOneToOneDescriptor] and value:
        other_model = getattr(Model, field).get_queryset().model
        # in case is a dictionary, we have to retrieve the object with every key
        if isinstance(value, dict):
            real_vals = {}
            for key, real_val in value.items():
                real_vals[key] = _get_real_obj(other_model, key, real_val)
            value = other_model.objects.get_or_create(**real_vals)[0]
        # it is just the primary key serialized
        else:
            value = other_model.objects.get(pk=value)
    return value

def _create_object(Model, data):
    mtm, no_mtm = {}, {}
    for field, value in data.items():
        if type(getattr(Model, field)) is ManyToManyDescriptor:
            mtm[field] = value
        else:
            value = _get_real_obj(Model, field ,value)
            no_mtm[field] = value
    try:
        o = Model.objects.get(**no_mtm)
    except Model.DoesNotExist:
        o = Model(**no_mtm)
        o.full_clean()
        o.save()
        for field, value in mtm.items():
            attribute = getattr(o, field)
            attribute.set(value)
    
def migrate(apps, schema_editor):
    Parameter = apps.get_model("api_app", "Parameter")
    PluginConfig = apps.get_model("api_app", "PluginConfig")    
    python_path = plugin.pop("model")
    Model = apps.get_model(*python_path.split("."))
    _create_object(Model, plugin)
    for param in params:
        _create_object(Parameter, param)
    for value in values:
        _create_object(PluginConfig, value)

"""  # noqa

    @staticmethod
    def _reverse_migrate_template():
        return """
def reverse_migrate(apps, schema_editor):
    python_path = plugin.pop("model")
    Model = apps.get_model(*python_path.split("."))
    Model.objects.get(name=plugin["name"]).delete()
"""

    def _body_template(self, app):
        return """

class Migration(migrations.Migration):

    dependencies = [
        ('api_app', '{0}'),
        ('{1}', '{2}'),
    ]

    operations = [
        migrations.RunPython(
            migrate, reverse_migrate
        )
    ]
""".format(
            self._get_last_migration("api_app"), app, self._get_last_migration(app)
        )

    @staticmethod
    def _get_last_migration(app):
        from django.db.migrations.recorder import MigrationRecorder

        return MigrationRecorder.Migration.objects.filter(app=app).latest("id").name

    def _migration_file(self, obj, serializer_class, app):
        obj_data, param_data, values_data = self._get_serialization(
            obj, serializer_class
        )
        return """{0}
plugin = {1}

params = {2}

values = {3}

{4}
{5}
{6}
        """.format(  # noqa
            self._imports(),
            str(json.loads(json.dumps(obj_data))),
            str(json.loads(json.dumps(param_data))),
            str(json.loads(json.dumps(values_data))),
            self._migrate_template(),
            self._reverse_migrate_template(),
            self._body_template(app),
        )

    def _name_file(self, obj, app):
        from django.db.migrations.autodetector import MigrationAutodetector

        last_migration_number = MigrationAutodetector.parse_number(
            self._get_last_migration(app)
        )
        return (
            f"{str(int(last_migration_number) + 1).rjust(4, '0')}"
            f"_{obj.snake_case_name}_{obj.name.lower()}.py"
        )

    @staticmethod
    def _save_file(name_file, content, app):
        path = "api_app" / PosixPath(app) / "migrations" / name_file
        if path.exists():
            raise RuntimeError(
                f"Migration {path} already exists."
                f" Please apply migration before create a new one"
            )
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)

    def handle(self, *args, **options):
        config_name = options["plugin_name"]
        config_class = options["plugin_class"]

        class_, serializer_class = (
            (AnalyzerConfig, AnalyzerConfigSerializerForMigration)
            if config_class == AnalyzerConfig.__name__
            else (ConnectorConfig, ConnectorConfigSerializerForMigration)
            if config_class == ConnectorConfig.__name__
            else (VisualizerConfig, VisualizerConfigSerializerForMigration)
            if config_class == VisualizerConfig.__name__
            else (IngestorConfig, IngestorConfigSerializerForMigration)
            if config_class == IngestorConfig.__name__
            else (PivotConfig, PivotConfigSerializerForMigration)
        )
        obj = class_.objects.get(name=config_name)
        app = obj._meta.app_label
        content = self._migration_file(obj, serializer_class, app)
        name_file = self._name_file(obj, app)
        self._save_file(name_file, content, app)
        self.stdout.write(
            self.style.SUCCESS(f"Migration {name_file} created with success")
        )
