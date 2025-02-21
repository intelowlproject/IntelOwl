# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging
import tarfile
import tempfile
from typing import Dict
from unittest.mock import patch

import maxminddb
import requests
from django.core.files import File
from django.utils import timezone
from geoip2.database import Reader
from geoip2.errors import AddressNotFoundError, GeoIP2Error
from geoip2.models import ASN, City, Country

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from api_app.analyzers_manager.models import AnalyzerSourceFile
from api_app.helpers import calculate_sha256
from api_app.models import PluginConfig
from tests.mock_utils import if_mock_connections

logger = logging.getLogger(__name__)


class Maxmind(classes.ObservableAnalyzer):
    _api_key_name: str
    _supported_dbs: [str] = ["GeoLite2-Country", "GeoLite2-City", "GeoLite2-ASN"]
    _default_db_extension: str = ".mmdb"

    def run(self):
        maxmind_final_result: {} = {}
        maxmind_errors: [] = []
        source_files = AnalyzerSourceFile.objects.filter(
            python_module=self.python_module
        )
        if not source_files:
            raise AnalyzerRunException("No source file found")

        for source_file in source_files:
            maxmind_result, maxmind_error = self._query_single_db(source_file)

            if maxmind_error:
                maxmind_errors.append(maxmind_error["error"])
            elif maxmind_result:
                logger.info(
                    f"maxmind result: {maxmind_result} in {source_file.file_name}"
                )
                maxmind_final_result.update(maxmind_result)
            else:
                logger.warning(
                    f"maxmind result not available in {source_file.file_name}"
                )

        if maxmind_errors:
            for error_msg in maxmind_errors:
                self.report.errors.append(error_msg)
            self.report.save()
        return maxmind_final_result

    def _query_single_db(self, source_file) -> (dict, dict):
        result: ASN | City | Country

        logger.info(f"Query {source_file.file_name} for {self.observable_name}")

        with Reader(source_file.file, mode=maxminddb.MODE_FD) as reader:
            try:
                if "ASN" in source_file.file_name:
                    result = reader.asn(self.observable_name)
                elif "Country" in source_file.file_name:
                    result = reader.country(self.observable_name)
                elif "City" in source_file.file_name:
                    result = reader.city(self.observable_name)
            except AddressNotFoundError:
                reader.close()
                logger.info(
                    f"Query for observable '{self.observable_name}' "
                    "didn't produce any results in any db."
                )
                return {}, {}
            except (GeoIP2Error, maxminddb.InvalidDatabaseError) as e:
                error_message = f"GeoIP2 database error: {e}"
                logger.exception(error_message)
                return {}, {"error": error_message}
            else:
                reader.close()
                return result.raw, {}

    @classmethod
    def get_db_names(cls) -> [str]:
        return [db_name + cls._default_db_extension for db_name in cls._supported_dbs]

    @classmethod
    def _get_api_key(cls):
        for plugin in PluginConfig.objects.filter(
            parameter__python_module=cls.python_module,
            parameter__is_secret=True,
            parameter__name="api_key_name",
        ):
            if plugin.value:
                return plugin.value
        return None

    @classmethod
    def update(cls) -> bool:
        auth_token = cls._get_api_key()
        general_update = False
        if auth_token:
            for db_name in cls._supported_dbs:
                request_data = {
                    "url": (
                        "https://download.maxmind.com/app/geoip_download?edition_id="
                        f"{db_name}&license_key={auth_token}&suffix=tar.gz"
                    )
                }
                file_name = f"{db_name}{cls._default_db_extension}"
                update = cls.update_source_file(
                    request_data,
                    file_name,
                )
                if update:
                    general_update = True
        else:
            logger.error("Missing api key")
        return general_update

    @classmethod
    def update_source_file(cls, request_data: Dict, file_name) -> bool:
        # check if file is updated
        logger.info(
            f"Source file update started with request data {request_data}, file name {file_name} and python module {cls.python_module}"
        )
        update = False
        response = requests.get(**request_data)
        response.raise_for_status()
        # extract maxmind db file
        db_name = file_name.replace(cls._default_db_extension, "")

        with tempfile.TemporaryDirectory() as tempdirname:
            tar_db_path = f"{tempdirname}/{db_name}.tar.gz"
            with open(tar_db_path, "wb") as f:
                f.write(response.content)
            tf = tarfile.open(tar_db_path)
            tf.extractall(tempdirname)

            for counter in range(10):
                formatted_date = (
                    timezone.now().date() - timezone.timedelta(days=counter)
                ).strftime("%Y%m%d")

                try:
                    file_path = f"{tempdirname}/{db_name}_{formatted_date}/{db_name}{cls._default_db_extension}"
                    with open(
                        file_path,
                        "rb",
                    ) as f:
                        logger.info(f"Found file {file_path}")
                        mmdb_file = File(f, name=file_name)

                        sha_res = calculate_sha256(mmdb_file.file.read())
                        source_file = AnalyzerSourceFile.objects.filter(
                            file_name=file_name, python_module=cls.python_module
                        ).first()
                        # check if source file exists
                        if source_file:
                            logger.info(f"Found source file {source_file}")
                            # check if source file needs to be updated
                            if source_file.sha256 != sha_res:
                                logger.info("About to update source file")
                                source_file.file.delete()
                                source_file.file = mmdb_file
                                source_file.sha256 = sha_res
                                source_file.save()
                                update = True
                        else:
                            logger.info(
                                f"About to create new source file with file name {file_name} and python module {cls.python_module}"
                            )
                            AnalyzerSourceFile.objects.create(
                                file_name=file_name,
                                python_module=cls.python_module,
                                file=mmdb_file,
                                sha256=sha_res,
                            )
                            update = True

                    break
                except FileNotFoundError:
                    logger.info(f"{file_path} not found")
                    continue

        return update

    @classmethod
    def _monkeypatch(cls):
        # completely skip because does not work without connection.
        patches = [if_mock_connections(patch.object(cls, "run", return_value={}))]
        return super()._monkeypatch(patches=patches)

    def _update_data_model(self, data_model) -> None:
        from api_app.analyzers_manager.models import AnalyzerReport

        super()._update_data_model(data_model)
        org = self.report.report.get("autonomous_system_organization", None)
        if org:
            org = org.lower()
            self.report: AnalyzerReport
            if org in ["fastly", "cloudflare", "akamai"]:
                data_model.evaluation = (
                    self.report.data_model_class.EVALUATIONS.CLEAN.value
                )
            elif org in [
                "zscaler",
                "palo alto networks",
                "microdata service srl",
                "forcepoint",
            ]:
                data_model.evaluation = (
                    self.report.data_model_class.EVALUATIONS.TRUSTED.value
                )
            elif org in ["stark industries"]:
                data_model.evaluation = (
                    self.report.data_model_class.EVALUATIONS.SUSPICIOUS.value
                )
