import shlex
import subprocess

from django.conf import settings
from django.core.management.base import BaseCommand
from django.utils import autoreload


class Command(BaseCommand):
    @staticmethod
    def add_arguments(parser):
        parser.add_argument(
            "-c", "--command", type=str, help="Celery command", required=True
        )

    def handle(self, *args, **options):
        if not settings.DEBUG:
            self.stdout.write(self.style.ERROR("Not runnable if in production mode"))

        autoreload.run_with_reloader(self._restart_celery, argument=options["command"])

    def _restart_celery(self, argument):
        self.run("pkill celery")
        self.run(f"/usr/local/bin/celery {argument}")

    def run(self, cmd):
        subprocess.run(shlex.split(cmd), check=True)
