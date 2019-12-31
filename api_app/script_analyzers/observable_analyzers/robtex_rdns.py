import json
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

        try:
            url = 'https://freeapi.robtex.com/pdns/reverse/{}'.format(observable_name)
            response = requests.get(url)
            response.raise_for_status()
            result = response.text.split('\r\n')
        except requests.ConnectionError as e:
            raise AnalyzerRunException("connection error: {}".format(e))
        else:
            loaded_results = []
            for item in result:
                if len(item) > 0:
                    loaded_results.append(json.loads(item))

        # pprint.pprint(loaded_results)
        report['report'] = loaded_results
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

