from django.core.management.base import BaseCommand
from api_app.core.update_checker import check_for_update

class Command(BaseCommand):
    help = "Check for newer IntelOwl releases"

    def handle(self, *args, **options):
        check_for_update()
        self.stdout.write(self.style.SUCCESS("Update check completed"))
