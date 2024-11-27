import abc
import base64
import logging
import time
from datetime import datetime, timedelta
from typing import Dict, List, Tuple

import requests
from django.core.cache import cache
from rest_framework.response import Response

from api_app.analyzers_manager.classes import BaseAnalyzerMixin
from api_app.analyzers_manager.constants import ObservableTypes
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from api_app.choices import ObservableClassification
from certego_saas.ext.pagination import CustomPageNumberPagination

logger = logging.getLogger(__name__)


class PaginationMixin:
    """
    Mixin to add pagination and caching support to a Django Rest Framework view.

    Attributes:
        pagination_class (CustomPageNumberPagination): The pagination class to use for paginating results.
    """

    pagination_class = CustomPageNumberPagination

    def list(self, request, *args, **kwargs):
        """
        Lists the objects, applying pagination and caching the results.

        Args:
            request (Request): The DRF request instance.
            *args: Variable length argument list.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Response: The paginated and cached response containing serialized data.
        """
        cache_name = (
            f"list_{self.serializer_class.Meta.model.__name__}_{request.user.username}"
        )
        queryset = self.filter_queryset(self.get_queryset())
        page = self.paginate_queryset(queryset)

        if page is not None:
            objects = queryset.filter(pk__in=[plugin.pk for plugin in page])
            if "page" in request.query_params and "page_size" in request.query_params:
                cache_name += (
                    f"_{request.query_params['page']}_"
                    f"{request.query_params['page_size']}"
                )
            cache_hit = cache.get(cache_name)
            if cache_hit is None:
                logger.debug(f"View {cache_name} cache not hit")
                serializer = self.get_serializer(objects, many=True)
                data = serializer.data
                cache.set(cache_name, value=data, timeout=60 * 60 * 24 * 7)
            else:
                logger.debug(f"View {cache_name} cache hit")
                data = cache_hit
                cache.touch(cache_name, timeout=60 * 60 * 24 * 7)
            return self.get_paginated_response(data)
        else:
            cache_hit = cache.get(cache_name)

            if cache_hit is None:
                serializer = self.get_serializer(queryset, many=True)
                data = serializer.data
                cache.set(cache_name, value=data, timeout=60 * 60 * 24 * 7)
            else:
                data = cache_hit
                cache.touch(cache_name, timeout=60 * 60 * 24 * 7)

        return Response(data)


class VirusTotalv3BaseMixin(metaclass=abc.ABCMeta):
    url = "https://www.virustotal.com/api/v3/"

    # If you want to query a specific subpath of the base endpoint, i.e: `analyses`
    url_sub_path: str
    _api_key_name: str
    ObservableTypes = ObservableTypes

    @property
    def headers(self) -> dict:
        return {"x-apikey": self._api_key_name}

    def _perform_get_request(
        self, uri: str, ignore_404: bool = False, **kwargs
    ) -> Dict:
        return self._perform_request(uri, method="GET", ignore_404=ignore_404, **kwargs)

    def _perform_post_request(self, uri: str, ignore_404: bool = False, **kwargs):
        return self._perform_request(
            uri, method="POST", ignore_404=ignore_404, **kwargs
        )

    def _perform_request(
        self, uri: str, method: str, ignore_404: bool = False, **kwargs
    ) -> Dict:
        error = None
        try:
            url = self.url + uri
            if method == "GET":
                response = requests.get(url, headers=self.headers, **kwargs)
            elif method == "POST":
                response = requests.post(url, headers=self.headers, **kwargs)
            else:
                raise NotImplementedError()
            logger.info(f"requests done to: {response.request.url} ")
            logger.debug(f"text: {response.text}")
            result = response.json()
            # https://developers.virustotal.com/reference/errors
            error = result.get("error", {})
            # this case is not a real error,...
            # .. it happens when a requested object is not found and that's normal
            if not ignore_404 or not response.status_code == 404:
                response.raise_for_status()
        except Exception as e:
            error_message = f"Raised Error: {e}. Error data: {error}"
            raise AnalyzerRunException(error_message)
        return result, response

    # return available relationships from file mimetype
    @classmethod
    def _get_relationship_for_classification(cls, obs_clfn: str, iocs: bool) -> List:
        # reference: https://developers.virustotal.com/reference/metadata
        if obs_clfn == cls.ObservableTypes.DOMAIN:
            relationships = [
                "communicating_files",
                "historical_whois",
                "referrer_files",
                "resolutions",
                "siblings",
                "subdomains",
                "collections",
                "historical_ssl_certificates",
            ]
        elif obs_clfn == cls.ObservableTypes.IP:
            relationships = [
                "communicating_files",
                "historical_whois",
                "referrer_files",
                "resolutions",
                "collections",
                "historical_ssl_certificates",
            ]
        elif obs_clfn == cls.ObservableTypes.URL:
            relationships = [
                "last_serving_ip_address",
                "collections",
                "network_location",
            ]
        elif obs_clfn == cls.ObservableTypes.HASH:
            if iocs:
                relationships = [
                    "contacted_domains",
                    "contacted_ips",
                    "contacted_urls",
                ]
            else:
                relationships = [
                    # behaviors is necessary to check if there are sandbox analysis
                    "behaviours",
                    "bundled_files",
                    "comments",
                    "contacted_domains",
                    "contacted_ips",
                    "contacted_urls",
                    "execution_parents",
                    "pe_resource_parents",
                    "votes",
                    "distributors",
                    "pe_resource_children",
                    "dropped_files",
                    "collections",
                ]
        else:
            raise AnalyzerRunException(
                f"Not supported observable type {obs_clfn}. "
                "Supported are: hash, ip, domain and url."
            )
        return relationships

    # configure requests params from file mimetype to get relative relationships
    def _get_requests_params_and_uri(
        self, obs_clfn: str, observable_name: str, iocs: bool
    ) -> Tuple[Dict, str, List]:
        params = {}
        # in this way, you just retrieved metadata about relationships
        # if you like to get all the data about specific relationships,...
        # ..you should perform another query
        # check vt3 API docs for further info
        relationships_requested = self._get_relationship_for_classification(
            obs_clfn, iocs
        )
        if obs_clfn == self.ObservableTypes.DOMAIN:
            uri = f"domains/{observable_name}"
        elif obs_clfn == self.ObservableTypes.IP:
            uri = f"ip_addresses/{observable_name}"
        elif obs_clfn == self.ObservableTypes.URL:
            url_id = (
                base64.urlsafe_b64encode(observable_name.encode()).decode().strip("=")
            )
            uri = f"urls/{url_id}"
        elif obs_clfn == self.ObservableTypes.HASH:
            uri = f"files/{observable_name}"
        else:
            raise AnalyzerRunException(
                f"Not supported observable type {obs_clfn}. "
                "Supported are: hash, ip, domain and url."
            )

        if relationships_requested:
            # this won't cost additional quota
            # it just helps to understand if there is something to look for there
            # so, if there is, we can make API requests without wasting quotas
            params["relationships"] = ",".join(relationships_requested)
        if hasattr(self, "url_sub_path") and self.url_sub_path:
            if not self.url_sub_path.startswith("/"):
                uri += "/"
            uri += self.url_sub_path
        return params, uri, relationships_requested

    def _fetch_behaviour_summary(self, observable_name: str) -> Dict:
        endpoint = f"files/{observable_name}/behaviour_summary"
        logger.info(f"Requesting behaviour summary from {endpoint}")
        result, _ = self._perform_get_request(endpoint, ignore_404=True)
        return result

    def _fetch_sigma_analyses(self, observable_name: str) -> Dict:
        endpoint = f"sigma_analyses/{observable_name}"
        logger.info(f"Requesting sigma analyses from {endpoint}")
        result, _ = self._perform_get_request(endpoint, ignore_404=True)
        return result

    def _vt_download_file(self, file_hash: str) -> bytes:
        try:
            endpoint = self.url + f"files/{file_hash}/download"
            logger.info(f"Requesting file from {endpoint}")
            response = requests.get(endpoint, headers=self.headers)
            if not isinstance(response.content, bytes):
                raise ValueError("VT downloaded file is not instance of bytes")
        except Exception as e:
            error_message = f"Cannot download the file {file_hash}. Raised Error: {e}."
            raise AnalyzerRunException(error_message)
        return response.content

    # perform a query in VT and return the results
    # ref: https://developers.virustotal.com/reference/intelligence-search
    def _vt_intelligence_search(
        self,
        query: str,
        limit: int,
        order_by: str,
    ) -> Dict:
        logger.info(f"Running VirusTotal intelligence search query: {query}")

        limit = min(limit, 300)  # this is a limit forced by VT service
        params = {
            "query": query,
            "limit": limit,
        }
        if order_by:
            params["order"] = order_by

        result, _ = self._perform_get_request("intelligence/search", params=params)
        return result

    def _vt_get_iocs_from_file(self, sample_hash: str) -> Dict:
        try:
            params, uri, relationships_requested = self._get_requests_params_and_uri(
                self.ObservableTypes.HASH, sample_hash, True
            )
            logger.info(f"Requesting IOCs {relationships_requested} from {uri}")
            result, response = self._perform_get_request(
                uri, ignore_404=True, params=params
            )
            if response.status_code != 404:
                relationships = result.get("data", {}).get("relationships", {})
                contacted_ips = [
                    i["id"]
                    for i in relationships.get("contacted_ips", {}).get("data", [])
                ]
                contacted_domains = [
                    i["id"]
                    for i in relationships.get("contacted_domains", {}).get("data", [])
                ]
                contacted_urls = [
                    i["context_attributes"]["url"]
                    for i in relationships.get("contacted_urls", {}).get("data", [])
                ]
                return {
                    "contacted_ips": contacted_ips,
                    "contacted_urls": contacted_urls,
                    "contacted_domains": contacted_domains,
                }
        except Exception as e:
            logger.error(
                "something went wrong when extracting iocs"
                f" for sample {sample_hash}: {e}"
            )


class VirusTotalv3AnalyzerMixin(
    VirusTotalv3BaseMixin, BaseAnalyzerMixin, metaclass=abc.ABCMeta
):
    # How many times we poll the VT API for scan results
    max_tries: int
    # IntelOwl would sleep for this time between each poll to VT APIs
    poll_distance: int
    # How many times we poll the VT API for RE-scan results (samples already available to VT)
    rescan_max_tries: int
    # IntelOwl would sleep for this time between each poll to VT APIs after having started a RE-scan
    rescan_poll_distance: int
    # Include a summary of behavioral analysis reports alongside default scan report.
    # This will cost additional quota.
    include_behaviour_summary: bool
    # Include sigma analysis report alongside default scan report.
    # This will cost additional quota.
    include_sigma_analyses: bool
    # If the sample is old, it would be rescanned.
    # This will cost additional quota.
    force_active_scan_if_old: bool
    # How many days are required to consider a scan old to force rescan
    days_to_say_that_a_scan_is_old: int
    # Include a list of relationships to request if available.
    # Full list here https://developers.virustotal.com/reference/metadata.
    # This will cost additional quota.
    relationships_to_request: list
    # Number of elements to retrieve for each relationships
    relationships_elements: int

    def config(self, runtime_configuration: Dict):
        super().config(runtime_configuration)
        self.force_active_scan = self._job.tlp == self._job.TLP.CLEAR.value

    def _get_relationship_limit(self, relationship: str) -> int:
        # by default, just extract the first element
        limit = self.relationships_elements
        # resolutions data can be more valuable and it is not lot of data
        if relationship == "resolutions":
            limit = 40
        return limit

    def _vt_get_relationships(
        self,
        observable_name: str,
        relationships_requested: list,
        uri: str,
        result: dict,
    ) -> None:
        try:
            # skip relationship request if something went wrong
            if "error" not in result:
                relationships_in_results = result.get("data", {}).get(
                    "relationships", {}
                )
                for relationship in self.relationships_to_request:
                    if relationship not in relationships_requested:
                        result[relationship] = {
                            "error": "not supported, review configuration."
                        }
                    else:
                        found_data = relationships_in_results.get(relationship, {}).get(
                            "data", []
                        )
                        if found_data:
                            logger.info(
                                f"found data in relationship {relationship} "
                                f"for observable {observable_name}."
                                " Requesting additional information about"
                            )
                            rel_uri = (
                                uri + f"/{relationship}"
                                f"?limit={self._get_relationship_limit(relationship)}"
                            )
                            logger.debug(f"requesting uri: {rel_uri}")
                            response = requests.get(
                                self.url + rel_uri, headers=self.headers
                            )
                            result[relationship] = response.json()
        except Exception as e:
            logger.error(
                "something went wrong when extracting relationships"
                f" for observable {observable_name}: {e}"
            )

    def _get_url_prefix_postfix(self, result: Dict) -> Tuple[str, str]:
        uri_postfix = self._job.observable_name
        if self._job.observable_classification == ObservableClassification.DOMAIN.value:
            uri_prefix = "domain"
        elif self._job.observable_classification == ObservableClassification.IP.value:
            uri_prefix = "ip-address"
        elif self._job.observable_classification == ObservableClassification.URL.value:
            uri_prefix = "url"
            uri_postfix = result.get("data", {}).get("id", self._job.sha256)
        else:  # hash
            uri_prefix = "search"
        return uri_prefix, uri_postfix

    def _vt_scan_file(self, md5: str, rescan_instead: bool = False) -> Dict:
        if rescan_instead:
            logger.info(f"(Job: {self.job_id}, {md5}) -> VT analyzer requested rescan")
            files = {}
            uri = f"files/{md5}/analyse"
            poll_distance = self.rescan_poll_distance
            max_tries = self.rescan_max_tries
        else:
            logger.info(f"(Job: {self.job_id}, {md5}) -> VT analyzer requested scan")
            try:
                binary = self._job.file.read()
            except Exception:
                raise AnalyzerRunException(
                    "IntelOwl error: couldn't retrieve the binary"
                    f" to perform a scan (Job: {self.job_id}, {md5})"
                )
            files = {"file": binary}
            uri = "files"
            poll_distance = self.poll_distance
            max_tries = self.max_tries

        result, _ = self._perform_post_request(uri, files=files)

        result_data = result.get("data", {})
        scan_id = result_data.get("id", "")
        if not scan_id:
            raise AnalyzerRunException(
                "no scan_id given by VirusTotal to retrieve the results"
                f" (Job: {self.job_id}, {md5})"
            )
        # max 5 minutes waiting
        got_result = False
        uri = f"analyses/{scan_id}"
        logger.info(
            "Starting POLLING for Scan results. "
            f"Poll Distance {poll_distance}, tries {max_tries}, ScanID {scan_id}"
            f" (Job: {self.job_id}, {md5})"
        )
        for chance in range(max_tries):
            time.sleep(poll_distance)
            result, _ = self._perform_get_request(uri, files=files)
            analysis_status = (
                result.get("data", {}).get("attributes", {}).get("status", "")
            )
            logger.info(
                f"[POLLING] (Job: {self.job_id}, {md5}) -> "
                f"GET VT/v3/_vt_scan_file #{chance + 1}/{self.max_tries} "
                f"status:{analysis_status}"
            )
            if analysis_status == "completed":
                got_result = True
                break

        result = {}
        if got_result:
            # retrieve the FULL report, not only scans results.
            # If it's a new sample, it's free of charge.
            result = self._vt_get_report(self.ObservableTypes.HASH, md5)
        else:
            message = (
                f"[POLLING] (Job: {self.job_id}, {md5}) -> "
                "max polls tried, no result"
            )
            # if we tried a rescan, we can still use the old report
            if rescan_instead:
                logger.info(message)
            else:
                raise AnalyzerRunException(message)

        return result

    def _vt_poll_for_report(
        self,
        observable_name: str,
        params: Dict,
        uri: str,
        obs_clfn: str,
    ) -> Dict:
        result = {}
        already_done_active_scan_because_report_was_old = False
        for chance in range(self.max_tries):
            logger.info(
                f"[POLLING] (Job: {self.job_id}, observable {observable_name}) -> "
                f"GET VT/v3/_vt_get_report #{chance + 1}/{self.max_tries}"
            )

            result, response = self._perform_get_request(
                uri, ignore_404=True, params=params
            )

            # if it is not a file, we don't need to perform any scan
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
                        some_days_ago = datetime.utcnow() - timedelta(
                            days=self.days_to_say_that_a_scan_is_old
                        )
                        if some_days_ago > scan_date_time:
                            logger.info(
                                f"hash {observable_name} found on VT with AV reports"
                                " and scan is older than"
                                f" {self.days_to_say_that_a_scan_is_old} days.\n"
                                "We will force the analysis again"
                            )
                            # the "rescan" option will burn quotas.
                            # We should reduce the polling at the minimum
                            extracted_result = self._vt_scan_file(
                                observable_name, rescan_instead=True
                            )
                            # if we were able to do a successful rescan,
                            # overwrite old report
                            if extracted_result:
                                result = extracted_result
                            already_done_active_scan_because_report_was_old = True
                        else:
                            logger.info(
                                f"hash {observable_name} found on VT"
                                " with AV reports and scan is recent"
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

        return result

    def _vt_include_behaviour_summary(
        self,
        result: Dict,
        observable_name: str,
    ) -> Dict:
        sandbox_analysis = (
            result.get("data", {})
            .get("relationships", {})
            .get("behaviours", {})
            .get("data", [])
        )
        if sandbox_analysis:
            logger.info(
                f"found {len(sandbox_analysis)} sandbox analysis"
                f" for {observable_name},"
                " requesting the additional details"
            )
            return self._fetch_behaviour_summary(observable_name)

    def _vt_include_sigma_analyses(
        self,
        result: Dict,
        observable_name: str,
    ) -> Dict:
        sigma_analysis = (
            result.get("data", {})
            .get("relationships", {})
            .get("sigma_analysis", {})
            .get("data", [])
        )
        if sigma_analysis:
            logger.info(
                f"found {len(sigma_analysis)} sigma analysis"
                f" for {observable_name},"
                " requesting the additional details"
            )
            return self._fetch_sigma_analyses(observable_name)

    def _vt_get_report(
        self,
        obs_clfn: str,
        observable_name: str,
    ) -> Dict:
        params, uri, relationships_requested = self._get_requests_params_and_uri(
            obs_clfn, observable_name, False
        )

        result = self._vt_poll_for_report(
            observable_name,
            params,
            uri,
            obs_clfn,
        )

        if obs_clfn == self.ObservableTypes.HASH:
            # Include behavioral report, if flag enabled
            # Attention: this will cost additional quota!
            if self.include_behaviour_summary:
                result["behaviour_summary"] = self._vt_include_behaviour_summary(
                    result, observable_name
                )

            # Include sigma analysis report, if flag enabled
            # Attention: this will cost additional quota!
            if self.include_sigma_analyses:
                result["sigma_analyses"] = self._vt_include_sigma_analyses(
                    result, observable_name
                )

        if self.relationships_to_request:
            self._vt_get_relationships(
                observable_name, relationships_requested, uri, result
            )

        uri_prefix, uri_postfix = self._get_url_prefix_postfix(result)
        result["link"] = f"https://www.virustotal.com/gui/{uri_prefix}/{uri_postfix}"

        return result
