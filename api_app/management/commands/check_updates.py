import logging

from django.core.management.base import BaseCommand, CommandError

from api_app.core.update_checker import check_for_update

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = "Check for newer IntelOwl releases"

    def handle(self, *args, **options):
        try:
            success, message = check_for_update()
        except Exception:
            logger.exception("Unexpected error during update check")
            raise CommandError("Unexpected error during update check. See logs for details.")

        if not success:
            logger.info("Update check failed: %s", message)
            raise CommandError(message)

        self.stdout.write(self.style.SUCCESS(message))
