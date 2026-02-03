import logging
import shlex
import subprocess

from django.conf import settings
from django.core.management.base import BaseCommand
from django.utils import autoreload

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    @staticmethod
    def add_arguments(parser):
        parser.add_argument("-c", "--command", type=str, help="Celery command", required=True)

    def handle(self, *args, **options):
        if not settings.DEBUG:
            self.stdout.write(self.style.ERROR("Not runnable in production mode"))
            return
        logger.info("Starting celery with autoreload")
        autoreload.run_with_reloader(self._restart_celery, argument=options["command"])

    def _restart_celery(self, argument):
        self.run("pkill celery")
        self.run(f"/usr/local/bin/celery {argument}")

    @staticmethod
    def run(cmd):
        subprocess.run(shlex.split(cmd), check=True)
