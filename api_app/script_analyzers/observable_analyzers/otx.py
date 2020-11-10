import OTXv2

from ipaddress import AddressValueError, IPv4Address
from urllib.parse import urlparse

from api_app.exceptions import AnalyzerRunException
from api_app.script_analyzers import classes
from intel_owl import secrets


class OTX(classes.ObservableAnalyzer):
    def set_config(self, additional_config_params):
        self.api_key_name = additional_config_params.get("api_key_name", "OTX_KEY")
        self.verbose = additional_config_params.get("verbose", False)

    def run(self):
        api_key = secrets.get_secret(self.api_key_name)
        if not api_key:
            raise AnalyzerRunException(
                f"No API key retrieved with name: {self.api_key_name}"
            )

        otx = OTXv2.OTXv2(api_key)

        obs_clsf = self.observable_classification
        to_analyze_observable = self.observable_name
        if obs_clsf == "ip":
            otx_type = OTXv2.IndicatorTypes.IPv4
        elif obs_clsf == "url":
            to_analyze_observable = urlparse(self.observable_name).hostname
            try:
                to_analyze_observable = IPv4Address(to_analyze_observable)
            except AddressValueError:
                otx_type = OTXv2.IndicatorTypes.DOMAIN
            else:
                otx_type = OTXv2.IndicatorTypes.IPv4
            if not to_analyze_observable:
                raise AnalyzerRunException("extracted observable is None")
        elif obs_clsf == "domain":
            otx_type = OTXv2.IndicatorTypes.DOMAIN
        elif obs_clsf == "hash":
            otx_type = OTXv2.IndicatorTypes.FILE_HASH_MD5
        else:
            raise AnalyzerRunException(
                f"not supported observable classification {obs_clsf}"
            )

        result = {}
        try:
            details = otx.get_indicator_details_full(otx_type, to_analyze_observable)
        except (OTXv2.BadRequest, OTXv2.NotFound) as e:
            result["error"] = str(e)
        else:
            result["pulses"] = (
                details.get("general", {}).get("pulse_info", {}).get("pulses", [])
            )
            # for some observables the output could really be overwhelming
            if not self.verbose and result["pulses"]:
                result["pulses"] = result["pulses"][:20]
            result["geo"] = details.get("geo", {})
            result["malware_samples"] = [
                d.get("hash", "") for d in details.get("malware", {}).get("data", [])
            ]
            result["passive_dns"] = details.get("passive_dns", {}).get(
                "passive_dns", []
            )
            result["reputation"] = details.get("reputation", {}).get("reputation", None)
            result["url_list"] = details.get("url_list", {}).get("url_list", [])
            result["analysis"] = details.get("analysis", {}).get("analysis", {})
            if not self.verbose:
                if result["analysis"] and "plugins" in result["analysis"]:
                    result["analysis"]["plugins"] = "removed because too long"

        return result
