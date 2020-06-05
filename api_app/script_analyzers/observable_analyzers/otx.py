import traceback
import logging

import OTXv2

from ipaddress import AddressValueError, IPv4Address
from urllib.parse import urlparse

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
        api_key_name = additional_config_params.get("api_key_name", "")
        if not api_key_name:
            api_key_name = "OTX_KEY"
        api_key = secrets.get_secret(api_key_name)
        if not api_key:
            raise AnalyzerRunException("no api key retrieved")

        otx = OTXv2.OTXv2(api_key)

        to_analyze_observable = observable_name
        if observable_classification == "ip":
            otx_type = OTXv2.IndicatorTypes.IPv4
        elif observable_classification == "url":
            to_analyze_observable = urlparse(observable_name).hostname
            try:
                to_analyze_observable = IPv4Address(to_analyze_observable)
            except AddressValueError:
                otx_type = OTXv2.IndicatorTypes.DOMAIN
            else:
                otx_type = OTXv2.IndicatorTypes.IPv4
            if not to_analyze_observable:
                raise AnalyzerRunException("extracted observable is None")
        elif observable_classification == "domain":
            otx_type = OTXv2.IndicatorTypes.DOMAIN
        elif observable_classification == "hash":
            otx_type = OTXv2.IndicatorTypes.FILE_HASH_MD5
        else:
            raise AnalyzerRunException(
                "not supported observable classification {}".format(
                    observable_classification
                )
            )

        result = {}
        details = otx.get_indicator_details_full(otx_type, to_analyze_observable)
        # pprint.pprint(details)

        result["pulses"] = (
            details.get("general", {}).get("pulse_info", {}).get("pulses", [])
        )
        result["geo"] = details.get("geo", {})
        result["malware_samples"] = [
            d.get("hash", "") for d in details.get("malware", {}).get("data", [])
        ]
        result["passive_dns"] = details.get("passive_dns", {}).get("passive_dns", [])
        result["reputation"] = details.get("reputation", {}).get("reputation", None)
        result["url_list"] = details.get("url_list", {}).get("url_list", [])
        result["analysis"] = details.get("analysis", {}).get("analysis", {})

        # pprint.pprint(result)
        report["report"] = result
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
        string_error = str(e)
        error_message = (
            "job_id:{} analyzer:{} observable_name:{} Unexpected error {}"
            "".format(job_id, analyzer_name, observable_name, e)
        )
        if "IP is private" in string_error:
            logger.warning(error_message)
        else:
            logger.exception(error_message)
        report["errors"].append(string_error)
        report["success"] = False
    else:
        report["success"] = True

    general.set_report_and_cleanup(job_id, report)

    logger.info(
        "ended analyzer {} job_id {} observable {}"
        "".format(analyzer_name, job_id, observable_name)
    )

    return report
