# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import os

from django.core.management.base import BaseCommand

from api_app.analyzers_manager.serializers import AnalyzerConfigSerializer
from api_app.connectors_manager.serializers import ConnectorConfigSerializer
from api_app.models import PluginConfig


class Command(BaseCommand):
    help = "Migrates secrets from env_file_app (pre-v4.0) to database"

    # Explicit function to facilitate testing
    @staticmethod
    def _get_env_var(name):
        return os.getenv(name)

    @classmethod
    def _migrate_secrets(cls, plugin_list, plugin_type, ignore_check):
        from django.contrib.auth import get_user_model

        if PluginConfig.objects.filter(type=plugin_type).exists() and not ignore_check:
            print(
                f"Skipping {plugin_type} secrets migration because "
                "there are already some secrets in the database."
            )
            return

        User = get_user_model()
        if not User.objects.filter(is_superuser=True).exists():
            raise Exception("Superuser must exist for secrets migration")
        for plugin in plugin_list:
            for secret_name in plugin["secrets"].keys():
                secret = plugin["secrets"][secret_name]
                if cls._get_env_var(secret["env_var_key"]):
                    if PluginConfig.objects.get_or_create(
                        attribute=secret_name,
                        value=cls._get_env_var(secret["env_var_key"]),
                        plugin_name=plugin["name"],
                        type=plugin_type,
                        config_type=PluginConfig.ConfigType.SECRET,
                        owner=User.objects.filter(is_superuser=True).first(),
                    )[1]:
                        print(
                            f"Migrated secret {secret['env_var_key']} "
                            f"for plugin {plugin['name']}"
                        )

    def add_arguments(self, parser):
        parser.add_argument("ignore_check", nargs="?", type=bool, default=False)

    def handle(self, *args, **options):
        ignore_check = options["ignore_check"]
        self._migrate_secrets(
            AnalyzerConfigSerializer.read_and_verify_config().values(),
            PluginConfig.PluginType.ANALYZER,
            ignore_check,
        )
        self._migrate_secrets(
            ConnectorConfigSerializer.read_and_verify_config().values(),
            PluginConfig.PluginType.CONNECTOR,
            ignore_check,
        )
        print(
            "Migration complete. Please delete all plugin secrets "
            "from docker/env_file_app."
        )
