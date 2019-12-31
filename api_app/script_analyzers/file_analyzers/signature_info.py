import traceback

from subprocess import Popen, DEVNULL, STDOUT, PIPE

from celery.exceptions import SoftTimeLimitExceeded
from celery.utils.log import get_task_logger

from api_app.exceptions import AnalyzerRunException
from api_app.script_analyzers import general

logger = get_task_logger(__name__)


def run(analyzer_name, job_id, filepath, filename, md5, additional_config_params):
    logger.info("started analyzer {} job_id {}"
                "".format(analyzer_name, job_id))
    report = general.get_basic_report_template(analyzer_name)
    p = None
    try:
        results = {
            'checksum_mismatch': False,
            'no_signature': False,
            'verified': False,
            'corrupted': False
        }

        command = ['osslsigncode', 'verify', filepath]
        p = Popen(command, stdin=DEVNULL, stdout=PIPE, stderr=PIPE)
        (out, err) = p.communicate()
        output = out.decode()

        if p.returncode == 1 and 'MISMATCH' in output:
            results['checksum_mismatch'] = True
        elif p.returncode != 0:
            raise AnalyzerRunException("osslsigncode return code is {}. Error: {}"
                                       "".format(p.returncode, err))

        if output:
            if 'No signature found' in output:
                results['no_signature'] = True
            if 'Signature verification: ok' in output:
                results['verified'] = True
            if 'Corrupt PE file' in output:
                results['corrupted'] = True
        else:
            raise AnalyzerRunException("osslsigncode gave no output?")

        report['report'] = results
    except AnalyzerRunException as e:
        error_message = "job_id:{} analyzer:{} md5:{} filename: {} Analyzer Error {}" \
                        "".format(job_id, analyzer_name, md5, filename, e)
        logger.error(error_message)
        report['errors'].append(error_message)
        report['success'] = False
    except SoftTimeLimitExceeded as e:
        error_message = "job_id:{} analyzer:{} md5:{} filename: {} Soft Time Limit Exceeded Error {}" \
                        "".format(job_id, analyzer_name, md5, filename, e)
        logger.error(error_message)
        report['errors'].append(str(e))
        report['success'] = False
        # we should stop the subprocesses in case we reach the time limit for the celery task
        if p:
            p.kill()
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

    # pprint.pprint(report)

    logger.info("ended analyzer {} job_id {}"
                "".format(analyzer_name, job_id))

    return report
