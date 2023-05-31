# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
from pathlib import PosixPath

from django.core.management import BaseCommand

from api_app.models import PluginConfig


class Command(BaseCommand):
    help = "Create migration file from pluginconfig saved inside the db"

    @staticmethod
    def add_arguments(parser):
        parser.add_argument(
            "plugin_config",
            type=int,
            help="PluginConfig pk to dump",
        )

    @staticmethod
    def _migrate_template(obj):
        return """
def migrate(apps, schema_editor):
    PluginConfig = apps.get_model("api_app", "PluginConfig")    
    pc = PluginConfig.objects.get(pk={0})
    pc.value = {1}
    pc.full_clean()
    pc.save()
""".format(  # noqa
            obj.pk, obj.value
        )

    @staticmethod
    def _reverse_migrate_template():
        return """
def reverse_migrate(apps, schema_editor):
    pass
"""

    def _body_template(self, app):
        return """
from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('api_app', '{0}'),
    ]

    operations = [
        migrations.RunPython(
            migrate, reverse_migrate
        )
    ]
""".format(
            self._get_last_migration(app),
        )

    @staticmethod
    def _get_last_migration(app):
        from django.db.migrations.recorder import MigrationRecorder

        return MigrationRecorder.Migration.objects.filter(app=app).latest("id").name

    def _migration_file(self, obj, app):
        return """
{0}
{1}
{2}
        """.format(
            self._migrate_template(obj),
            self._reverse_migrate_template(),
            self._body_template(app),
        )

    def _name_file(self, obj: PluginConfig, app):
        from django.db.migrations.autodetector import MigrationAutodetector

        last_migration_number = MigrationAutodetector.parse_number(
            self._get_last_migration(app)
        )
        return (
            f"{str(int(last_migration_number)+1).rjust(4, '0')}"
            f"_{obj.__class__.__name__.lower()}_{obj.parameter.name.lower()}.py"
        )

    @staticmethod
    def _save_file(name_file, content, app):
        with open(
            PosixPath(app) / "migrations" / name_file, "w", encoding="utf-8"
        ) as f:
            f.write(content)

    def handle(self, *args, **options):

        plugin_config_pk = options["plugin_config"]
        obj = PluginConfig.objects.get(pk=plugin_config_pk)
        app = obj._meta.app_label
        content = self._migration_file(obj, app)
        name_file = self._name_file(obj, app)
        self._save_file(name_file, content, app)
