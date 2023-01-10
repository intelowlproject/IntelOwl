# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import os

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand

from api_app.models import PluginConfig
from certego_saas.apps.organization.organization import Organization


class Command(BaseCommand):
    help = "Migrates secrets from a selected user to a selected org"

    # Explicit function to facilitate testing
    @staticmethod
    def _get_env_var(name):
        return os.getenv(name)

    @classmethod
    def _migrate_secrets_to_org(cls, user, organization):
        User = get_user_model()
        plugins_for_user = PluginConfig.objects.filter(
            owner=User.objects.get(username=user)
        )
        for plugin in plugins_for_user:
            plugin.organization = Organization.objects.get(name=organization)
            plugin.save()
            print(
                f"migrate secret {plugin.attribute} {plugin.plugin_name}"
                f" for org {organization}"
            )

    def add_arguments(self, parser):
        parser.add_argument("-u", "--user", required=True)
        parser.add_argument("-o", "--organization", required=True)

    def handle(self, *args, **options):
        user = options["user"]
        organization = options["organization"]
        self._migrate_secrets_to_org(user, organization)
        print("Migration complete")
