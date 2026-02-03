import json
import logging

from django.conf import settings
from django.core.management import BaseCommand
from elasticsearch import ApiError

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    # NOTE: this command is runned by uwsgi startup script

    help = "Create or update the index templates in Elasticsearch"

    def handle(self, *args, **options):
        if settings.ELASTICSEARCH_DSL_ENABLED and settings.ELASTICSEARCH_DSL_HOST:
            self.stdout.write("Creating/updating the templates...")
            # push template
            with open(
                settings.CONFIG_ROOT / "elastic_search_mappings" / "plugin_report.json"
            ) as file_content:
                try:
                    settings.ELASTICSEARCH_DSL_CLIENT.indices.put_template(
                        name="plugin-report", body=json.load(file_content)
                    )
                    success_msg = "created/updated Elasticsearch's template for plugin-report"
                    self.stdout.write(self.style.SUCCESS(success_msg))
                    logger.info(success_msg)
                except ApiError as error:
                    self.stdout.write(self.style.ERROR(error))
                    logger.critical(error)
        else:
            self.stdout.write(self.style.WARNING("Elasticsearch not active, templates not updated"))
