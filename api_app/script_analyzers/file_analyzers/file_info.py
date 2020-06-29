import hashlib
import pydeep
import traceback
import magic
import pyexifinfo
import logging

from api_app.exceptions import AnalyzerRunException
from api_app.script_analyzers import general

logger = logging.getLogger(__name__)


def run(analyzer_name, job_id, filepath, filename, md5, additional_config_params):
    logger.info("started analyzer {} job_id {}" "".format(analyzer_name, job_id))
    report = general.get_basic_report_template(analyzer_name)
    try:
        results = {}
        results["magic"] = magic.from_file(filepath)
        results["mimetype"] = magic.from_file(filepath, mime=True)
        results["filetype"] = pyexifinfo.fileType(filepath)

        exif_report = pyexifinfo.get_json(filepath)
        if exif_report:
            exif_report_cleaned = {
                key: value
                for key, value in exif_report[0].items()
                if not (key.startswith("File") or key.startswith("SourceFile"))
            }
            results["exiftool"] = exif_report_cleaned

        binary = general.get_binary(job_id)
        results["md5"] = hashlib.md5(binary).hexdigest()
        results["sha1"] = hashlib.sha1(binary).hexdigest()
        results["sha256"] = hashlib.sha256(binary).hexdigest()
        results["ssdeep"] = pydeep.hash_file(filepath).decode()

        report["report"] = results
    except AnalyzerRunException as e:
        error_message = (
            "job_id:{} analyzer:{} md5:{} filename: {} Analyzer Error {}"
            "".format(job_id, analyzer_name, md5, filename, e)
        )
        logger.error(error_message)
        report["errors"].append(error_message)
        report["success"] = False
    except Exception as e:
        traceback.print_exc()
        error_message = (
            "job_id:{} analyzer:{} md5:{} filename: {} Unexpected Error {}"
            "".format(job_id, analyzer_name, md5, filename, e)
        )
        logger.exception(error_message)
        report["errors"].append(str(e))
        report["success"] = False
    else:
        report["success"] = True

    general.set_report_and_cleanup(job_id, report)

    logger.info("ended analyzer {} job_id {}" "".format(analyzer_name, job_id))

    return report
