import socket
import traceback
import logging

from api_app.exceptions import AnalyzerRunException
from api_app.script_analyzers import general

logger = logging.getLogger(__name__)


def run(
    analyzer_name,
    job_id,
    observable_name,
    observable_classification,
    additional_config_params,
):
    logger.info(
        f"started analyzer {analyzer_name} job_id {job_id} observable {observable_name}"
    )
    report = general.get_basic_report_template(analyzer_name)
    try:
        results = {}
        if observable_classification != "hash":
            raise AnalyzerRunException(
                f"observable type {observable_classification} not supported"
            )

        results["found"] = False
        # reference: https://team-cymru.com/community-services/mhr/
        # if the resolution works, this means that the file is reported
        # as malware by Cymru
        resolutions = []
        try:
            query_to_perform = f"{observable_name}.malware.hash.cymru.com"
            domains = socket.gethostbyaddr(query_to_perform)
            resolutions = domains[2]
        except (socket.gaierror, socket.herror):
            logger.info(f"observable {observable_name} not found in HMR DB")
        if resolutions:
            results["found"] = True
        results["resolution_data"] = resolutions
        report["report"] = results

    except AnalyzerRunException as e:
        error_message = (
            f"job_id:{job_id} analyzer:{analyzer_name}"
            f" observable_name:{observable_name} Analyzer error {e}"
        )
        logger.error(error_message)
        report["errors"].append(error_message)
        report["success"] = False
    except Exception as e:
        traceback.print_exc()
        error_message = (
            f"job_id:{job_id} analyzer:{analyzer_name}"
            f" observable_name:{observable_name} Unexpected error {e}"
        )
        logger.exception(error_message)
        report["errors"].append(str(e))
        report["success"] = False
    else:
        report["success"] = True

    general.set_report_and_cleanup(job_id, report)

    logger.info(
        f"ended analyzer {analyzer_name} job_id {job_id} observable {observable_name}"
    )

    return report
