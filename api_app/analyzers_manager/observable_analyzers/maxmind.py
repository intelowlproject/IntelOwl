# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import datetime
import logging
import os
import shutil
import tarfile

import maxminddb
import requests
from django.conf import settings
from geoip2.database import Reader
from geoip2.errors import AddressNotFoundError, GeoIP2Error
from geoip2.models import ASN, City, Country

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import (
    AnalyzerConfigurationException,
    AnalyzerRunException,
)
from api_app.models import PluginConfig

logger = logging.getLogger(__name__)


class MaxmindDBManager:
    _supported_dbs: [str] = ["GeoLite2-Country", "GeoLite2-City", "GeoLite2-ASN"]
    _default_db_extension: str = ".mmdb"

    @classmethod
    def get_supported_dbs(cls) -> [str]:
        return [db_name + cls._default_db_extension for db_name in cls._supported_dbs]

    @classmethod
    def update_all_dbs(cls, api_key: str) -> bool:
        return all(cls._update_db(db, api_key) for db in cls._supported_dbs)

    def query_all_dbs(self, observable_query: str, api_key: str) -> (dict, dict):
        maxmind_final_result: {} = {}
        maxmind_errors: [] = []
        for db in self._supported_dbs:
            maxmind_result, maxmind_error = self._query_single_db(observable_query, db, api_key)

            if maxmind_error:
                maxmind_errors.append(maxmind_error["error"])
            elif maxmind_result:
                logger.info(f"maxmind result: {maxmind_result} in {db=}")
                maxmind_final_result.update(maxmind_result)
            else:
                logger.warning(f"maxmind result not available in {db=}")

        return maxmind_final_result, maxmind_errors

    @classmethod
    def _get_physical_location(cls, db: str) -> str:
        return f"{settings.MEDIA_ROOT}/{db}{cls._default_db_extension}"

    def _query_single_db(self, query_ip: str, db_name: str, api_key: str) -> (dict, dict):
        result: ASN | City | Country
        db_path: str = self._get_physical_location(db_name)
        self._check_and_update_db(api_key, db_name)

        logger.info(f"Query {db_name=} for {query_ip=}")
        with Reader(db_path) as reader:
            try:
                if "ASN" in db_name:
                    result = reader.asn(query_ip)
                elif "Country" in db_name:
                    result = reader.country(query_ip)
                elif "City" in db_name:
                    result = reader.city(query_ip)
            except AddressNotFoundError:
                reader.close()
                logger.info(f"Query for observable '{query_ip}' didn't produce any results in any db.")
                return {}, {}
            except (GeoIP2Error, maxminddb.InvalidDatabaseError) as e:
                error_message = f"GeoIP2 database error: {e}"
                logger.exception(error_message)
                return {}, {"error": error_message}
            else:
                reader.close()
                return result.raw, {}

    def _check_and_update_db(self, api_key: str, db_name: str):
        db_path = self._get_physical_location(db_name)
        if not os.path.isfile(db_path) and not self._update_db(db_name, api_key):
            raise AnalyzerRunException(
                f"failed extraction of maxmind db {db_name}, reached max number of attempts"
            )
        if not os.path.exists(db_path):
            raise maxminddb.InvalidDatabaseError(f"database location '{db_path}' does not exist")

    @classmethod
    def _update_db(cls, db: str, api_key: str) -> bool:
        if not api_key:
            raise AnalyzerConfigurationException(f"Unable to find api key for {cls.__name__}")

        try:
            logger.info(f"starting download of {db=} from maxmind")

            tar_db_path = cls._download_db(db, api_key)
            cls._extract_db_to_media_root(tar_db_path)
            directory_found = cls._remove_old_db(db)

            if not directory_found:
                return False

            logger.info(f"ended download of {db=} from maxmind")
            return True

        except Exception as e:
            logger.exception(e)
        return False

    @classmethod
    def _download_db(cls, db_name: str, api_key: str) -> str:
        url = (
            "https://download.maxmind.com/app/geoip_download?edition_id="
            f"{db_name}&license_key={api_key}&suffix=tar.gz"
        )
        response = requests.get(url)
        if response.status_code >= 300:
            raise AnalyzerRunException(
                f"failed request for new maxmind db {db_name}."
                f" Status code: {response.status_code}"
                f"\nResponse: {response.raw}"
            )

        return cls._write_db_to_filesystem(db_name, response.content)

    @classmethod
    def _write_db_to_filesystem(cls, db_name: str, content: bytes) -> str:
        tar_db_path = f"/tmp/{db_name}.tar.gz"
        logger.info(f"starting writing db {db_name} downloaded from maxmind to {tar_db_path}")
        with open(tar_db_path, "wb") as f:
            f.write(content)

        return tar_db_path

    @classmethod
    def _extract_db_to_media_root(cls, tar_db_path: str):
        logger.info(f"Started extracting {tar_db_path} to {settings.MEDIA_ROOT}.")
        tf = tarfile.open(tar_db_path)
        tf.extractall(str(settings.MEDIA_ROOT))
        logger.info(f"Finished extracting {tar_db_path} to {settings.MEDIA_ROOT}.")

    @classmethod
    def _remove_old_db(cls, db: str) -> bool:
        physical_db_location = cls._get_physical_location(db)
        today = datetime.datetime.now().date()
        counter = 0
        directory_found = False
        # this is because we do not know the exact date of the db we downloaded
        while counter < 10 or not directory_found:
            formatted_date = (today - datetime.timedelta(days=counter)).strftime("%Y%m%d")
            downloaded_db_path = (
                f"{settings.MEDIA_ROOT}/{db}_{formatted_date}/{db}{cls._default_db_extension}"
            )
            try:
                os.rename(downloaded_db_path, physical_db_location)
            except FileNotFoundError:
                logger.debug(f"{downloaded_db_path} not found move to the day before")
                counter += 1
            else:
                directory_found = True
                shutil.rmtree(f"{settings.MEDIA_ROOT}/{db}_{formatted_date}")
                logger.info(f"maxmind directory found {downloaded_db_path}")
        return directory_found


class Maxmind(classes.ObservableAnalyzer):
    _api_key_name: str
    _maxmind_db_manager: "MaxmindDBManager" = MaxmindDBManager()

    def run(self):
        maxmind_final_result, maxmind_errors = self._maxmind_db_manager.query_all_dbs(
            self.observable_name, self._api_key_name
        )
        if maxmind_errors:
            for error_msg in maxmind_errors:
                self.report.errors.append(error_msg)
            self.report.save()
        return maxmind_final_result

    @classmethod
    def get_db_names(cls) -> [str]:
        return cls._maxmind_db_manager.get_supported_dbs()

    @classmethod
    def _get_api_key(cls):
        for plugin in PluginConfig.objects.filter(
            parameter__python_module=cls.python_module,
            parameter__is_secret=True,
            parameter__name="_api_key_name",
        ):
            if plugin.value:
                return plugin.value
        return None

    @classmethod
    def update(cls) -> bool:
        auth_token = cls._get_api_key()
        if auth_token:
            return cls._maxmind_db_manager.update_all_dbs(cls._api_key_name)
        return False

    def _update_data_model(self, data_model) -> None:
        from api_app.analyzers_manager.models import AnalyzerReport

        super()._update_data_model(data_model)
        org = self.report.report.get("autonomous_system_organization", None)
        if org:
            org = org.lower()
            self.report: AnalyzerReport
            if org in ["fastly", "cloudflare", "akamai"]:
                data_model.evaluation = self.EVALUATIONS.TRUSTED.value
                data_model.reliability = 4
            elif org in [
                "zscaler",
                "palo alto networks",
                "microdata service srl",
                "forcepoint",
            ]:
                data_model.evaluation = self.EVALUATIONS.TRUSTED.value
                data_model.reliability = 8
            elif org in ["stark industries"]:
                data_model.evaluation = self.EVALUATIONS.MALICIOUS.value
                data_model.reliability = 4
