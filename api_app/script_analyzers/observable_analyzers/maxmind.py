import datetime
import os
import logging
import shutil
import tarfile
import traceback

import maxminddb
import requests

from api_app.exceptions import AnalyzerRunException
from api_app.script_analyzers import classes
from intel_owl import settings, secrets

logger = logging.getLogger(__name__)

db_names = ["GeoLite2-Country.mmdb", "GeoLite2-City.mmdb"]


class Maxmind(classes.ObservableAnalyzer):
    def set_config(self, additional_config_params):
        self.additional_config_params = additional_config_params

    def run(self):
        maxmind_final_result = {}
        for db in db_names:
            try:
                db_location = _get_db_location(db)
                if not os.path.isfile(db_location):
                    self.updater(self.additional_config_params, db)
                reader = maxminddb.open_database(db_location)
                maxmind_result = reader.get(self.observable_name)
                reader.close()
            except maxminddb.InvalidDatabaseError as e:
                error_message = f"Invalid database error: {e}"
                logger.exception(error_message)
                maxmind_result = {"error": error_message}
            logger.info(maxmind_result)
            maxmind_final_result.update(maxmind_result)

        return maxmind_final_result

    @staticmethod
    def updater(additional_config_params, db):
        db_location = _get_db_location(db)
        try:
            api_key_name = additional_config_params.get("api_key_name", "MAXMIND_KEY")
            api_key = secrets.get_secret(api_key_name)
            if not api_key:
                raise AnalyzerRunException(
                    f"No API key retrieved with name: '{api_key_name}'"
                )

            db_name_wo_ext = db[:-5]
            logger.info(f"starting download of db {db_name_wo_ext} from maxmind")
            url = (
                "https://download.maxmind.com/app/geoip_download?edition_id="
                f"{db_name_wo_ext}&license_key={api_key}&suffix=tar.gz"
            )
            r = requests.get(url)
            if r.status_code >= 300:
                raise AnalyzerRunException(
                    f"failed request for new maxmind db {db_name_wo_ext}."
                    f" Status code: {r.status_code}"
                )

            tar_db_path = f"/tmp/{db_name_wo_ext}.tar.gz"
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
                    f"{directory_to_extract_files}/"
                    f"{db_name_wo_ext}_{formatted_date}/{db}"
                )
                try:
                    os.rename(downloaded_db_path, db_location)
                except FileNotFoundError:
                    logger.debug(
                        f"{downloaded_db_path} not found move to the day before"
                    )
                    counter += 1
                else:
                    directory_found = True
                    shutil.rmtree(
                        f"{directory_to_extract_files}/"
                        f"{db_name_wo_ext}_{formatted_date}"
                    )

            if directory_found:
                logger.info(f"maxmind directory found {downloaded_db_path}")
            else:
                raise AnalyzerRunException(
                    f"failed extraction of maxmind db {db_name_wo_ext},"
                    f" reached max number of attempts"
                )

            logger.info(f"ended download of db {db_name_wo_ext} from maxmind")

        except Exception as e:
            traceback.print_exc()
            logger.exception(str(e))

        return db_location


def _get_db_location(db):
    return f"{settings.MEDIA_ROOT}/{db}"
