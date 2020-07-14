import datetime
import os
import logging
import tarfile
import traceback

import maxminddb
import requests

from api_app.exceptions import AnalyzerRunException
from api_app.script_analyzers import classes
from intel_owl import settings, secrets

logger = logging.getLogger(__name__)

db_name = "GeoLite2-Country.mmdb"
database_location = f"{settings.MEDIA_ROOT}/{db_name}"


class Maxmind(classes.ObservableAnalyzer):
    def set_config(self, additional_config_params):
        self.additional_config_params = additional_config_params

    def run(self):
        try:
            if not os.path.isfile(database_location):
                self.updater(self.additional_config_params)
            reader = maxminddb.open_database(database_location)
            maxmind_result = reader.get(self.observable_name)
            reader.close()
        except maxminddb.InvalidDatabaseError as e:
            error_message = f"Invalid database error: {e}"
            logger.exception(error_message)
            maxmind_result = {"error": error_message}

        if not maxmind_result:
            maxmind_result = {}

        return maxmind_result

    @staticmethod
    def updater(additional_config_params):
        try:
            api_key_name = additional_config_params.get("api_key_name", "MAXMIND_KEY")
            api_key = secrets.get_secret(api_key_name)
            if not api_key:
                raise AnalyzerRunException(
                    f"No API key retrieved with name: '{api_key_name}'"
                )

            logger.info("starting download of db from maxmind")
            url = (
                "https://download.maxmind.com/app/geoip_download?edition_id="
                f"GeoLite2-Country&license_key={api_key}&suffix=tar.gz"
            )
            r = requests.get(url)
            if r.status_code >= 300:
                raise AnalyzerRunException(
                    f"failed request for new maxmind db. Status code: {r.status_code}"
                )

            tar_db_path = "/tmp/GeoLite2-Country.tar.gz"
            with open(tar_db_path, "wb") as f:
                f.write(r.content)

            tf = tarfile.open(tar_db_path)
            directory_to_extract_files = settings.MEDIA_ROOT
            tf.extractall(directory_to_extract_files)

            today = datetime.datetime.now().date()
            counter = 0
            directory_found = False
            downloaded_db_path = ""
            # this is because we do not know the exact date of the db we downloaded
            while counter < 10 or not directory_found:
                date_to_check = today - datetime.timedelta(days=counter)
                formatted_date = date_to_check.strftime("%Y%m%d")
                downloaded_db_path = (
                    "{}/GeoLite2-Country_{}/GeoLite2-Country.mmdb"
                    "".format(directory_to_extract_files, formatted_date)
                )
                try:
                    os.rename(downloaded_db_path, database_location)
                except FileNotFoundError:
                    logger.debug(
                        f"{downloaded_db_path} not found move to the day before"
                    )
                    counter += 1
                else:
                    directory_found = True

            if directory_found:
                logger.info(f"maxmind directory found {downloaded_db_path}")
            else:
                raise AnalyzerRunException(
                    "failed extraction of maxmind db, reached max number of attempts"
                )

            logger.info("ended download of db from maxmind")

        except Exception as e:
            traceback.print_exc()
            logger.exception(str(e))

        return database_location
