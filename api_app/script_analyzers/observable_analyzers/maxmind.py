import datetime
import os
import logging
import tarfile
import traceback

import maxminddb
import requests

from api_app.exceptions import AnalyzerRunException
from api_app.script_analyzers import general
from intel_owl import settings, secrets

logger = logging.getLogger(__name__)

db_name = "GeoLite2-Country.mmdb"
database_location = "{}/{}".format(settings.MEDIA_ROOT, db_name)


def run(
    analyzer_name,
    job_id,
    observable_name,
    observable_classification,
    additional_config_params,
):
    logger.info(
        "started analyzer {} job_id {} observable {}"
        "".format(analyzer_name, job_id, observable_name)
    )
    report = general.get_basic_report_template(analyzer_name)
    try:
        try:
            if not os.path.isfile(database_location):
                updater(additional_config_params)
            reader = maxminddb.open_database(database_location)
            maxmind_result = reader.get(observable_name)
            reader.close()
        except maxminddb.InvalidDatabaseError as e:
            error_message = "invalid database error: {}".format(e)
            logger.exception(error_message)
            maxmind_result = {"error": error_message}

        if not maxmind_result:
            maxmind_result = {}
        # pprint.pprint(maxmind_result)
        report["report"] = maxmind_result
    except AnalyzerRunException as e:
        error_message = (
            "job_id:{} analyzer:{} observable_name:{} Analyzer error {}"
            "".format(job_id, analyzer_name, observable_name, e)
        )
        logger.error(error_message)
        report["errors"].append(error_message)
        report["success"] = False
    except Exception as e:
        traceback.print_exc()
        error_message = (
            "job_id:{} analyzer:{} observable_name:{} Unexpected error {}"
            "".format(job_id, analyzer_name, observable_name, e)
        )
        logger.exception(error_message)
        report["errors"].append(str(e))
        report["success"] = False
    else:
        report["success"] = True

    general.set_report_and_cleanup(job_id, report)

    logger.info(
        "finished analyzer {} job_id {} observable {}"
        "".format(analyzer_name, job_id, observable_name)
    )

    return report


def updater(additional_config_params):

    try:
        api_key_name = additional_config_params.get("api_key_name", "MAXMIND_KEY")
        api_key = secrets.get_secret(api_key_name)
        if not api_key:
            raise AnalyzerRunException("no api key retrieved")

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
                    "{} not found move to the day before".format(downloaded_db_path)
                )
                counter += 1
            else:
                directory_found = True

        if directory_found:
            logger.info("maxmind directory found {}".format(downloaded_db_path))
        else:
            raise AnalyzerRunException(
                "failed extraction of maxmind db, reached max number of attempts"
            )

        logger.info("ended download of db from maxmind")

    except Exception as e:
        traceback.print_exc()
        logger.exception(str(e))

    return database_location
