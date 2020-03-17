import traceback
import requests

from celery.utils.log import get_task_logger

from api_app.exceptions import AnalyzerRunException
from api_app.script_analyzers import general

logger = get_task_logger(__name__)


def run(analyzer_name, job_id, observable_name, observable_classification, additional_config_params):
    logger.info("started analyzer {} job_id {} observable {}"
                "".format(analyzer_name, job_id, observable_name))
    report = general.get_basic_report_template(analyzer_name)
    try:
        if observable_classification=="hash":
            filehash = observable_name
        else: 
            raise AnalyzerRunException(f"not supported observable type {observable_classification}. Supported are: hash")

        post_data = {
            "query": "get_info",
            "hash": filehash
        }

        url = 'https://mb-api.abuse.ch/api/v1/'
        response = requests.post(url, data=post_data)
        response.raise_for_status()

        json_response = response.json()
        report['report'] = json_response
      
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

    general.set_report_and_cleanup(job_id, report, logger)

    logger.info("ended analyzer {} job_id {} observable {}"
                "".format(analyzer_name, job_id, observable_name))

    return report
