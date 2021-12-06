# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import base64
import logging
import time
from datetime import datetime, timedelta

import requests

from api_app.analyzers_manager.classes import BaseAnalyzerMixin
from api_app.exceptions import AnalyzerRunException

logger = logging.getLogger(__name__)


class VirusTotalv3AnalyzerMixin(BaseAnalyzerMixin):
    base_url = "https://www.virustotal.com/api/v3/"

    def set_params(self, params):
        # CARE!!!! VT is normally used with paid quotas!!!
        # Do not change these values without knowing what you are doing!
        self.max_tries = params.get("max_tries", 10)
        self.poll_distance = params.get("poll_distance", 30)
        self.include_behaviour_summary = params.get("include_behaviour_summary", False)
        self.include_sigma_analyses = params.get("include_sigma_analyses", False)
        self.force_active_scan = params.get("force_active_scan", False)
        self.force_active_scan_if_old = params.get("force_active_scan_if_old", False)

    @property
    def headers(self) -> dict:
        return {"x-apikey": self._secrets["api_key_name"]}

    def _vt_get_report(
        self,
        obs_clfn: str,
        observable_name: str,
    ) -> dict:
        result = {}
        already_done_active_scan_because_report_was_old = False
        params, uri = self._get_requests_params_and_uri(obs_clfn, observable_name)
        for chance in range(self.max_tries):
            try:
                logger.info(
                    f"[POLLING] (Job: {self.job_id}, observable {observable_name}) -> "
                    f"GET VT/v3/_vt_get_report #{chance + 1}/{self.max_tries}"
                )
                response = requests.get(
                    self.base_url + uri, params=params, headers=self.headers
                )
                # this case is not a real error,...
                # .. it happens when a requested object is not found and that's normal
                if not response.status_code == 404:
                    response.raise_for_status()
            except requests.RequestException as e:
                raise AnalyzerRunException(e)

            result = response.json()

            if obs_clfn != self.ObservableTypes.HASH:
                break

            # this is an option to force active scan...
            # .. in the case the file is not in the VT DB
            # you need the binary too for this case, ..
            # .. otherwise it would fail if it's not available
            if response.status_code == 404:
                logger.info(f"hash {observable_name} not found on VT")
                if self.force_active_scan:
                    logger.info(f"forcing VT active scan for hash {observable_name}")
                    result = self._vt_scan_file(observable_name)
                    result["performed_active_scan"] = True
                break
            else:
                # we should consider the chance that the very sample was already...
                # ...sent and VT is already analyzing it.
                # In this case, just perform a little poll for the result
                attributes = result.get("data", {}).get("attributes", {})
                last_analysis_results = attributes.get("last_analysis_results", {})
                if last_analysis_results:
                    # at this time, if the flag if set,
                    # we are going to force the analysis again for old samples
                    if (
                        self.force_active_scan_if_old
                        and not already_done_active_scan_because_report_was_old
                    ):
                        scan_date = attributes.get("last_analysis_date", 0)
                        scan_date_time = datetime.fromtimestamp(scan_date)
                        thirty_days_ago = datetime.utcnow() - timedelta(days=30)
                        if thirty_days_ago > scan_date_time:
                            logger.info(
                                f"hash {observable_name} found on VT with AV reports"
                                f" and scan is older than 30 days.\n"
                                f"We will force the analysis again"
                            )
                            # the "rescan" option will burn quotas.
                            # We should reduce the polling at the minimum
                            result = self._vt_scan_file(
                                observable_name,
                                rescan_instead=True,
                                max_tries=2,
                                poll_distance=120,
                            )
                            already_done_active_scan_because_report_was_old = True
                        else:
                            logger.info(
                                f"hash {observable_name} found on VT"
                                f" with AV reports and scan is recent"
                            )
                            break
                    else:
                        logger.info(
                            f"hash {observable_name} found on VT with AV reports"
                        )
                        break
                else:
                    extra_polling_times = chance + 1
                    base_log = f"hash {observable_name} found on VT withOUT AV reports,"
                    if extra_polling_times == self.max_tries:
                        logger.warning(
                            f"{base_log} reached max tries ({self.max_tries})"
                        )
                        result["reached_max_tries_and_no_av_report"] = True
                    else:
                        logger.info(f"{base_log} performing another request...")
                        result["extra_polling_times"] = extra_polling_times
                        time.sleep(self.poll_distance)

        if already_done_active_scan_because_report_was_old:
            result["performed_rescan_because_report_was_old"] = True

        # Include behavioral report, if flag enabled
        if self.include_behaviour_summary:
            result["behaviour_summary"] = self._fetch_behaviour_summary(observable_name)

        # Include sigma analysis report, if flag enabled
        if self.include_sigma_analyses:
            result["sigma_analyses"] = self._fetch_sigma_analyses(observable_name)

        return result

    def _vt_scan_file(
        self, md5: str, rescan_instead: bool = False, max_tries=None, poll_distance=None
    ) -> dict:
        # This can be overwritten to allow different configurations
        # Do not change this if you do not know what you are doing.
        # This impacts paid quota usage
        max_tries = max_tries if max_tries else self.max_tries
        poll_distance = poll_distance if poll_distance else self.poll_distance
        try:
            binary = self._job.file.read()
        except Exception:
            raise AnalyzerRunException("couldn't retrieve the binary to perform a scan")

        if rescan_instead:
            logger.info(f"(Job: {self.job_id}, {md5}) -> VT analyzer requested rescan")
            files = {}
            uri = f"files/{md5}/analyse"
        else:
            logger.info(f"(Job: {self.job_id}, {md5}) -> VT analyzer requested scan")
            files = {"file": binary}
            uri = "files"

        try:
            response = requests.post(
                self.base_url + uri, files=files, headers=self.headers
            )
            response.raise_for_status()
        except requests.RequestException as e:
            raise AnalyzerRunException(e)
        result = response.json()

        result_data = result.get("data", {})
        scan_id = result_data.get("id", "")
        if not scan_id:
            raise AnalyzerRunException(
                "no scan_id given by VirusTotal to retrieve the results"
            )
        # max 5 minutes waiting
        got_result = False
        uri = f"analyses/{scan_id}"
        for chance in range(max_tries):
            time.sleep(poll_distance)
            try:
                response = requests.get(self.base_url + uri, headers=self.headers)
                response.raise_for_status()
            except requests.RequestException as e:
                raise AnalyzerRunException(e)
            json_response = response.json()
            analysis_status = (
                json_response.get("data", {}).get("attributes", {}).get("status", "")
            )
            logger.info(
                f"[POLLING] (Job: {self.job_id}, {md5}) -> "
                f"GET VT/v3/_vt_scan_file #{chance + 1}/{self.max_tries} "
                f"status:{analysis_status}"
            )
            if analysis_status == "completed":
                got_result = True
                break

        if not got_result and not rescan_instead:
            raise AnalyzerRunException(
                f"[POLLING] (Job: {self.job_id}, {md5}) -> "
                f"max polls tried, no result"
            )

        # retrieve the FULL report, not only scans results.
        # If it's a new sample, it's free of charge.
        return self._vt_get_report(self.ObservableTypes.HASH, md5)

    def _fetch_behaviour_summary(self, observable_name: str) -> dict:
        try:
            endpoint = f"files/{observable_name}/behaviour_summary"
            uri = self.base_url + endpoint
            response = requests.get(uri, headers=self.headers)

            if not response.status_code == 404:
                response.raise_for_status()

        except requests.RequestException as e:
            raise AnalyzerRunException(e)

        return response.json()

    def _fetch_sigma_analyses(self, observable_name: str) -> dict:
        try:
            endpoint = f"sigma_analyses/{observable_name}"
            uri = self.base_url + endpoint
            response = requests.get(uri, headers=self.headers)

            if not response.status_code == 404:
                response.raise_for_status()

        except requests.RequestException as e:
            raise AnalyzerRunException(e)

        return response.json()

    @classmethod
    def _get_requests_params_and_uri(cls, obs_clfn: str, observable_name: str):
        params = {}
        # in this way, you just retrieved metadata about relationships
        # if you like to get all the data about specific relationships,...
        # ..you should perform another query
        # check vt3 API docs for further info
        if obs_clfn == cls.ObservableTypes.DOMAIN:
            relationships_requested = [
                "communicating_files",
                "downloaded_files",
                "historical_whois",
                "referrer_files",
                "resolutions",
                "siblings",
                "subdomains",
                "urls",
            ]
            uri = f"domains/{observable_name}"
        elif obs_clfn == cls.ObservableTypes.IP:
            relationships_requested = [
                "communicating_files",
                "downloaded_files",
                "historical_whois",
                "referrer_files",
                "resolutions",
                "urls",
            ]
            uri = f"ip_addresses/{observable_name}"
        elif obs_clfn == cls.ObservableTypes.URL:
            relationships_requested = [
                "downloaded_files",
                "analyses",
                "last_serving_ip_address",
                "redirecting_urls",
                "submissions",
            ]
            url_id = (
                base64.urlsafe_b64encode(observable_name.encode()).decode().strip("=")
            )
            uri = f"urls/{url_id}"
        elif obs_clfn == cls.ObservableTypes.HASH:
            relationships_requested = [
                "behaviours",
                "bundled_files",
                "comments",
                "compressed_parents",
                "contacted_domains",
                "contacted_ips",
                "contacted_urls",
                "execution_parents",
                "itw_urls",
                "overlay_parents",
                "pcap_parents",
                "pe_resource_parents",
                "votes",
            ]
            uri = f"files/{observable_name}"
        else:
            raise AnalyzerRunException(
                f"Not supported observable type {obs_clfn}. "
                "Supported are: hash, ip, domain and url."
            )

        if relationships_requested:
            params["relationships"] = ",".join(relationships_requested)

        return params, uri
