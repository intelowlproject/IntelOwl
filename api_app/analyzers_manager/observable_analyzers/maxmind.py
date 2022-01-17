# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import datetime
import logging
import os
import shutil
import tarfile
import traceback

import maxminddb
import requests
from django.conf import settings

from api_app.analyzers_manager import classes
from api_app.exceptions import AnalyzerRunException
from intel_owl import secrets
from tests.mock_utils import if_mock_connections, patch

logger = logging.getLogger(__name__)

db_names = ["GeoLite2-Country.mmdb", "GeoLite2-City.mmdb"]


class Maxmind(classes.ObservableAnalyzer):
    def set_params(self, params):
        self.params = params

    def run(self):
        maxmind_final_result = {}
        for db in db_names:
            try:
                db_location = _get_db_location(db)
                if not os.path.isfile(db_location):
                    self.updater(self.params, db)
                reader = maxminddb.open_database(db_location)
                maxmind_result = reader.get(self.observable_name)
                reader.close()
            except maxminddb.InvalidDatabaseError as e:
                error_message = f"Invalid database error: {e}"
                logger.exception(error_message)
                maxmind_result = {"error": error_message}
            logger.info(f"maxmind result: {maxmind_result}")
            if maxmind_result:
                maxmind_final_result.update(maxmind_result)
            else:
                logger.warning("maxmind result not available")

        return maxmind_final_result

    @classmethod
    def updater(cls, params, db):
        # FIXME @eshaan7: dont hardcode api key name
        api_key = secrets.get_secret("MAXMIND_KEY")
        db_location = _get_db_location(db)
        try:

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

    @classmethod
    def _monkeypatch(cls):
        # completely skip because does not work without connection.
        patches = [if_mock_connections(patch.object(cls, "run", return_value={}))]
        return super()._monkeypatch(patches=patches)


def _get_db_location(db):
    return f"{settings.MEDIA_ROOT}/{db}"
