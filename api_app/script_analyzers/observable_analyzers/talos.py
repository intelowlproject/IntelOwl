import os
import logging
import traceback
import requests

from api_app.exceptions import AnalyzerRunException
from api_app.script_analyzers import general
from intel_owl import settings

logger = logging.getLogger(__name__)

db_name = "talos_ip_blacklist.txt"
database_location = "{}/{}".format(settings.MEDIA_ROOT, db_name)


def run(analyzer_name, job_id, observable_name, observable_classification, additional_config_params):
    logger.info("started analyzer {} job_id {} observable {}"
                "".format(analyzer_name, job_id, observable_name))
    report = general.get_basic_report_template(analyzer_name)
    try:
        result = {'found': False}
        if not os.path.isfile(database_location):
            updater()

        with open(database_location, "r") as f:
            db = f.read()

        db_list = db.split('\n')
        # pprint.pprint(db_list)
        if observable_name in db_list:
            result['found'] = True

        # pprint.pprint(result)
        report['report'] = result
    except AnalyzerRunException as e:
        error_message = "job_id:{} analyzer:{} observable_name:{} Analyzer error {}" \
                        "".format(job_id, analyzer_name, observable_name, e)
        logger.error(error_message)
        report['errors'].append(error_message)
        report['success'] = False
    except Exception as e:
        traceback.print_exc()
        error_message = "job_id:{} analyzer:{} observable_name:{} Unexpected error {}" \
                        "".format(job_id, analyzer_name, observable_name, e)
        logger.exception(error_message)
        report['errors'].append(str(e))
        report['success'] = False
    else:
        report['success'] = True

    general.set_report_and_cleanup(job_id, report)

    logger.info("finished analyzer {} job_id {} observable {}"
                "".format(analyzer_name, job_id, observable_name))

    return report


def updater():

    try:
        logger.info("starting download of db from talos")
        url = "https://www.talosintelligence.com/documents/ip-blacklist"
        r = requests.get(url)
        r.raise_for_status()

        with open(database_location, "w") as f:
            f.write(r.content.decode())

        if not os.path.exists(database_location):
            raise AnalyzerRunException("failed extraction of talos db")

        logger.info("ended download of db from talos")

    except Exception as e:
        traceback.print_exc()
        logger.exception(e)

    return database_location

