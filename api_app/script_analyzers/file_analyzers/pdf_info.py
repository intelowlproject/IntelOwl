import traceback
import peepdf

from celery.utils.log import get_task_logger

from api_app.exceptions import AnalyzerRunException
from api_app.script_analyzers import general

logger = get_task_logger(__name__)


def run(analyzer_name, job_id, filepath, filename, md5, additional_config_params):
    logger.info("started analyzer {} job_id {}"
                "".format(analyzer_name, job_id))
    report = general.get_basic_report_template(analyzer_name)
    try:
        results = {}

        peepdf_analysis = []
        pdf_parser = peepdf.PDFCore.PDFParser()
        ret, pdf = pdf_parser.parse(filepath, True)
        if ret:
            peepdf_analysis['status_code'] = ret
        else:
            stats = pdf.getStats()
            for version in stats.get('Versions', []):
                version_dict = {
                    'events': version.get('Events', {}),
                    'actions': version.get('Actions', {}),
                    'urls': version.get('URLs', []),
                    'uris': version.get('URIs', []),
                    'elements': version.get('Elements', {}),
                    'vulns': version.get('Vulns', []),
                    'objects_with_js_code': version.get('Objects with JS code', [])
                }
                peepdf_analysis.append(version_dict)

        results['peepdf'] = peepdf_analysis

        # pprint.pprint(results)
        report['report'] = results
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
