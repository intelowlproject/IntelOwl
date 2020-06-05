import traceback
import logging
import pypssl

from api_app.exceptions import AnalyzerRunException
from api_app.script_analyzers import general
from intel_owl import secrets

logger = logging.getLogger(__name__)


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
        # You should save CIRCL credentials with this template: "<user>|<pwd>"
        credentials = secrets.get_secret("CIRCL_CREDENTIALS")
        if not credentials:
            raise AnalyzerRunException("no credentials retrieved")

        split_credentials = credentials.split("|")
        if len(split_credentials) != 2:
            raise AnalyzerRunException(
                "CIRCL credentials not properly configured."
                "Template to use: '<user>|<pwd>'"
            )

        user = split_credentials[0]
        pwd = split_credentials[1]

        pssl = pypssl.PyPSSL(basic_auth=(user, pwd))

        result = pssl.query(observable_name)

        certificates = []
        if result.get(observable_name, {}):
            certificates = list(result.get(observable_name).get("certificates", []))

        parsed_result = {"ip": observable_name, "certificates": []}
        for cert in certificates:
            subject = (
                result.get(observable_name)
                .get("subjects", {})
                .get(cert, {})
                .get("values", [])
            )
            if subject:
                parsed_result["certificates"].append(
                    {"fingerprint": cert, "subject": subject[0]}
                )

        # pprint.pprint(parsed_result)
        report["report"] = parsed_result
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
        "ended analyzer {} job_id {} observable {}"
        "".format(analyzer_name, job_id, observable_name)
    )

    return report
