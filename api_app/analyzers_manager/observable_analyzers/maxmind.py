# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import datetime
import logging
import os
import shutil
import tarfile

import geoip2  # noqa: F401
import geoip2.database  # noqa: F401
import requests
from django.conf.settings import MEDIA_ROOT

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import (
    AnalyzerConfigurationException,
    AnalyzerRunException,
)
from tests.mock_utils import if_mock_connections, patch

logger = logging.getLogger(__name__)


class MaxmindDBManager:
    supported_dbs: [str] = ["GeoLite2-Country", "GeoLite2-City", "GeoLite2-ASN"]
    default_db_extension: str = ".mmdb"

    @classmethod
    def get_physical_location(cls, db: str):
        return f"{MEDIA_ROOT}/{db}"

    @classmethod
    def update(cls, api_key: str) -> bool:
        return all(cls._update_db(db, api_key) for db in cls.supported_dbs)

    @classmethod
    def _update_db(cls, db: str, api_key: str) -> bool:
        if not api_key:
            raise AnalyzerConfigurationException(
                f"Unable to find api key for {cls.__name__}"
            )

        physical_db_location = cls.get_physical_location(db + cls.default_db_extension)
        try:
            tar_db_path = cls._download_db(db, api_key)

            cls._extract_db_to_media_root(tar_db_path)

            today = datetime.datetime.now().date()
            counter = 0
            directory_found = False
            downloaded_db_path = ""
            # this is because we do not know the exact date of the db we downloaded
            while counter < 10 or not directory_found:
                date_to_check = today - datetime.timedelta(days=counter)
                formatted_date = date_to_check.strftime("%Y%m%d")
                downloaded_db_path = (
                    f"{MEDIA_ROOT}/"
                    f"{db}_{formatted_date}/{db}{cls.default_db_extension}"
                )
                try:
                    os.rename(downloaded_db_path, physical_db_location)
                except FileNotFoundError:
                    logger.debug(
                        f"{downloaded_db_path} not found move to the day before"
                    )
                    counter += 1
                else:
                    directory_found = True
                    shutil.rmtree(f"{MEDIA_ROOT}/" f"{db}_{formatted_date}")

            if directory_found:
                logger.info(f"maxmind directory found {downloaded_db_path}")
            else:
                return False

            logger.info(f"ended download of db {db} from maxmind")
            return True

        except Exception as e:
            logger.exception(e)
        return False

    @classmethod
    def _extract_db_to_media_root(cls, tar_db_path: str):
        tf = tarfile.open(tar_db_path)
        tf.extractall(str(MEDIA_ROOT))

    @classmethod
    def _download_db(cls, db_name: str, api_key: str) -> str:
        logger.info(f"starting download of db {db_name} from maxmind")
        url = (
            "https://download.maxmind.com/app/geoip_download?edition_id="
            f"{db_name}&license_key={api_key}&suffix=tar.gz"
        )
        response = requests.get(url)
        if response.status_code >= 300:
            raise AnalyzerRunException(
                f"failed request for new maxmind db {db_name}."
                f" Status code: {response.status_code}"
            )

        tar_db_path = f"/tmp/{db_name}.tar.gz"
        with open(tar_db_path, "wb") as f:
            f.write(response.content)

        return tar_db_path

    @classmethod
    def get_supported_dbs(cls):
        return [db_name + cls.default_db_extension for db_name in cls.supported_dbs]


class Maxmind(classes.ObservableAnalyzer):
    _api_key_name: str
    maxmind_db_manager: "MaxmindDBManager" = MaxmindDBManager()

    def run(self):
        maxmind_final_result = {}
        for db in self.get_db_names():
            try:
                db_location = self.maxmind_db_manager.get_physical_location(db)
                if not os.path.isfile(db_location) and not self.update_databases():
                    raise AnalyzerRunException(
                        f"failed extraction of maxmind db {db},"
                        " reached max number of attempts"
                    )
                if not os.path.exists(db_location):
                    raise maxminddb.InvalidDatabaseError(  # noqa: F821
                        "database location does not exist"
                    )
                reader = maxminddb.open_database(db_location)  # noqa: F821
                maxmind_result = reader.get(self.observable_name)
                reader.close()
            except maxminddb.InvalidDatabaseError as e:  # noqa: F821
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
    def get_db_names(cls) -> [str]:
        return cls.maxmind_db_manager.get_supported_dbs()

    @classmethod
    def update_databases(cls) -> bool:
        return cls.maxmind_db_manager.update(cls._api_key_name)

    @classmethod
    def _monkeypatch(cls):
        # completely skip because does not work without connection.
        patches = [if_mock_connections(patch.object(cls, "run", return_value={}))]
        return super()._monkeypatch(patches=patches)
