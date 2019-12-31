import os
import time
import traceback
import requests

from celery.utils.log import get_task_logger

from api_app.exceptions import AnalyzerRunException
from api_app.script_analyzers import general
from api_app.utilities import get_now_date_only
from intel_owl import secrets

logger = get_task_logger(__name__)

base_url = "https://analyze.intezer.com/api/v2-0"


def run(analyzer_name, job_id, filepath, filename, md5, additional_config_params):
    logger.info("started analyzer {} job_id {}"
                "".format(analyzer_name, job_id))
    report = general.get_basic_report_template(analyzer_name)
    try:
        api_key_name = additional_config_params.get('api_key_name', '')
        if not api_key_name:
            api_key_name = "INTEZER_KEY"
        api_key = secrets.get_secret(api_key_name)
        if not api_key:
            raise AnalyzerRunException("no api key retrieved")

        intezer_token = os.environ.get('INTEZER_TOKEN', '')
        intezer_token_date = os.environ.get('INTEZER_TOKEN_DATE', '')
        today = get_now_date_only()
        if not intezer_token or intezer_token_date != today:
            intezer_token = _get_access_token(api_key)
            if not intezer_token:
                raise AnalyzerRunException("token extraction failed")

        binary = general.get_binary(job_id, logger)
        result = _intezer_scan_file(intezer_token, md5, filename, binary)

        # pprint.pprint(result)
        report['report'] = result
    except AnalyzerRunException as e:
        error_message = "job_id:{} analyzer:{} md5:{} filename: {} Analyzer Error {}" \
                        "".format(job_id, analyzer_name, md5, filename, e)
        logger.error(error_message)
        report['errors'].append(error_message)
        report['success'] = False
    except Exception as e:
        traceback.print_exc()
        error_message = "job_id:{} analyzer:{} md5:{} filename: {} Unexpected Error {}" \
                        "".format(job_id, analyzer_name, md5, filename, e)
        logger.exception(error_message)
        report['errors'].append(str(e))
        report['success'] = False
    else:
        report['success'] = True

    general.set_report_and_cleanup(job_id, report, logger)

    logger.info("ended analyzer {} job_id {}"
                "".format(analyzer_name, job_id))

    return report


def _get_access_token(api_key):
    # this should be done just once in a day
    response = requests.post(base_url + '/get-access-token', json={'api_key': api_key})
    response.raise_for_status()
    response_json = response.json()
    token = response_json.get('result', '')
    os.environ['INTEZER_TOKEN'] = token
    os.environ['INTEZER_TOKEN_DATE'] = get_now_date_only()
    return token


def _intezer_scan_file(intezer_token, md5, filename, binary):
    session = requests.session()
    session.headers['Authorization'] = 'Bearer {}'.format(intezer_token)

    name_to_send = filename if filename else md5
    files = {'file': (name_to_send, binary)}
    logger.info("intezer md5 {} sending sample for analysis".format(md5))
    response = session.post(base_url + '/analyze', files=files)
    if response.status_code != 201:
        raise AnalyzerRunException("failed analyze request, status code {}".format(response.status_code))

    max_tries = 200
    polling_time = 3
    for chance in range(max_tries):
        if response.status_code != 200:
            time.sleep(polling_time)
            logger.info("intezer md5 {} polling for result try n.{}".format(md5, chance+1))
            result_url = response.json()['result_url']
            response = session.get(base_url + result_url)
            response.raise_for_status()

    if response.status_code != 200:
        raise AnalyzerRunException("received max tries attempts")

    return response.json()
