import argparse
import os
from typing import Tuple

from django.core.management.base import BaseCommand
import markdown
import re
from certego_saas.apps.notifications.models import Notification


class Command(BaseCommand):
    help = "Create a notification with the latest changes"

    def __init__(self, *args, **kwargs):
        super(Command, self).__init__(*args, **kwargs)

        self.markdown: str
        self.last_release: str
        self.last_version: str
        self.last_content: str
        self.html: str

    def add_arguments(self, parser):
        parser.add_argument("path", type=str)
        parser.add_argument(
            "--release", nargs="?", type=str, default=r"[0-9].[0-9].[0-9]"
        )
        parser.add_argument(
            "--force", action=argparse.BooleanOptionalAction, default=False
        )
        parser.add_argument(
            "--debug", action=argparse.BooleanOptionalAction, default=False
        )

    def _read_file(self, path: str):
        if not os.path.exists(path):
            raise FileNotFoundError(f"File {path} not found")
        self.markdown = open(path, "r", encoding="utf-8").read()

    def _set_last_release(self, release_regex: str):
        self.last_version = re.findall(release_regex, self.markdown)[0]
        last_content = re.split(rf"##\s{release_regex}", self.markdown)[1]
        # we want the entire link
        self.last_release = f"{self.last_version}{last_content}"
        # remove [ ]
        self.last_version = self.last_version[1:-1]

    def _create_notification(self, force: bool = False) -> Tuple[Notification, bool]:
        title = f"New changes in {self.last_version}"
        if force:
            return (
                Notification.objects.create(
                    appname="INTELOWL", title=title, body=self.html
                ),
                True,
            )
        try:
            return Notification.objects.get(title__contains=title), False
        except Notification.DoesNotExist:
            return (
                Notification.objects.create(
                    appname="INTELOWL", title=title, body=self.html
                ),
                True,
            )

    def handle(self, *args, **options):
        self._read_file(options["path"])
        self._set_last_release(rf'\[v{options["release"]}\]')
        self.stdout.write(self.style.SUCCESS(f"Latest version: {self.last_version}"))
        if options["debug"]:
            self.stdout.write(f"Content:\n{self.last_release}")
        self.html = markdown.markdown(self.last_release)
        if options["debug"]:
            self.stdout.write(f"Html:\n{self.html}")
        notification, result = self._create_notification(options["force"])
        if result:
            self.stdout.write(
                self.style.SUCCESS(
                    f"New notification created with success"
                    f" for version {self.last_version}"
                )
            )
        else:
            self.stdout.write(
                self.style.ERROR(
                    f"Notification already exists" f" for version {self.last_version}"
                )
            )
