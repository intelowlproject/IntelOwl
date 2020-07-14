import traceback
import logging

from subprocess import Popen, DEVNULL, PIPE

from celery.exceptions import SoftTimeLimitExceeded

from api_app.exceptions import AnalyzerRunException
from api_app.script_analyzers import general

logger = logging.getLogger(__name__)


def run(analyzer_name, job_id, filepath, filename, md5, additional_config_params):
    logger.info(f"started analyzer {analyzer_name} job_id {job_id}")
    report = general.get_basic_report_template(analyzer_name)
    p1 = None
    p2 = None
    try:
        results = {}

        max_number_of_strings = int(
            additional_config_params.get("max_number_of_strings", 500)
        )
        max_characters_for_string = int(
            additional_config_params.get("max_characters_for_string", 1000)
        )

        # If set, this module will use Machine Learning feature
        # CARE!! ranked_strings could be cpu/ram intensive and very slow
        rank_strings = additional_config_params.get("rank_strings", False)

        # this is brutal, to resolve this with a proper library when available
        flare_command = ["flarestrings", filepath]
        p1 = Popen(flare_command, stdin=DEVNULL, stdout=PIPE, stderr=PIPE)
        if rank_strings:
            rank_command = ["rank_strings", "-l", str(max_number_of_strings)]
            p2 = Popen(rank_command, stdin=p1.stdout, stdout=PIPE, stderr=PIPE)
            out, err = p2.communicate()
            output_rankstrings = out.decode()

            if p2.returncode != 0:
                raise AnalyzerRunException(
                    f"rank_strings return code is {p2.returncode}. Error: {err}"
                )
            if len(output_rankstrings) == max_number_of_strings:
                results["exceeded_max_number_of_strings"] = True
            results["ranked_strings"] = [
                s[:max_characters_for_string] for s in output_rankstrings.split("\n")
            ]

        else:
            out, err = p1.communicate()
            output_flarestrings = out.decode()

            if p1.returncode != 0:
                raise AnalyzerRunException(
                    f"flarestrings return code is {p1.returncode}. Error: {err}"
                )
            if len(output_flarestrings) >= max_number_of_strings:
                results["exceeded_max_number_of_strings"] = True
            results["flare_strings"] = [
                s[:max_characters_for_string]
                for s in output_flarestrings.split("\n")[:max_number_of_strings]
            ]

        report["report"] = results
    except AnalyzerRunException as e:
        error_message = (
            f"job_id:{job_id} analyzer:{analyzer_name} md5:{md5} filename:{filename}."
            f" Analyzer Error: {e}"
        )
        logger.error(error_message)
        report["errors"].append(error_message)
        report["success"] = False
    except SoftTimeLimitExceeded as e:
        error_message = (
            f"job_id:{job_id} analyzer:{analyzer_name} md5:{md5} filename:{filename}."
            f" Soft Time Limit Exceeded Error: {e}"
        )
        logger.error(error_message)
        report["errors"].append(str(e))
        report["success"] = False
        # we should stop the subprocesses...
        # .. in case we reach the time limit for the celery task
        if p1:
            p1.kill()
        if p2:
            p2.kill()
    except Exception as e:
        traceback.print_exc()
        error_message = (
            f"job_id:{job_id} analyzer:{analyzer_name} md5:{md5} filename:{filename}."
            f" Unexpected Error: {e}"
        )
        logger.exception(error_message)
        report["errors"].append(str(e))
        report["success"] = False
    else:
        report["success"] = True

    general.set_report_and_cleanup(job_id, report)

    # pprint.pprint(report)

    logger.info(f"ended analyzer {analyzer_name} job_id {job_id}")

    return report
