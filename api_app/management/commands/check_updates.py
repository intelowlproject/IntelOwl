from django.core.management.base import BaseCommand
from api_app.core.update_checker import check_for_update


class Command(BaseCommand):
    help = "Check for newer IntelOwl releases"

    def handle(self, *args, **options):
        success, message = check_for_update()
        if success:
            self.stdout.write(self.style.SUCCESS(message))
        else:
            self.stdout.write(self.style.ERROR(message))
