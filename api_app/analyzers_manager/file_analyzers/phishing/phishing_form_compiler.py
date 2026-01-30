import logging
from datetime import date, timedelta
from typing import Dict
from urllib.parse import urljoin

import requests
from faker import Faker  # skipcq: BAN-B410
from lxml.etree import HTMLParser  # skipcq: BAN-B410
from lxml.html import document_fromstring
from requests import HTTPError, Response

from api_app.analyzers_manager.classes import FileAnalyzer
from api_app.models import PythonConfig

logger = logging.getLogger(__name__)


def xpath_query_on_page(page, xpath_selector: str) -> []:
    return page.xpath(xpath_selector)


class PhishingFormCompiler(FileAnalyzer):
    # good short guide for writing XPath expressions
    # https://upg-dh.newtfire.org/explainXPath.html
    # we're supporting XPath up to v3.1 with elementpath package
    xpath_form_selector: str = ""
    xpath_js_selector: str = ""
    proxy_address: str = ""

    name_matching: list = []
    cc_matching: list = []
    pin_matching: list = []
    cvv_matching: list = []
    expiration_date_matching: list = []
    user_agent: str = ""

    def __init__(
        self,
        config: PythonConfig,
        **kwargs,
    ):
        super().__init__(config, **kwargs)
        self.target_site: str = ""
        self.html_source_code: str = ""
        self.parsed_page = None
        self.args: [] = []
        self._name_text_input_mapping: {} = None
        self.FAKE_EMAIL_INPUT = None
        self.FAKE_PASSWORD_INPUT = None
        self.FAKE_TEL_INPUT = None

    def config(self, runtime_configuration: Dict):
        super().config(runtime_configuration)
        if hasattr(self._job, "pivot_parent"):
            # extract target site from parent job
            self.target_site = self._job.pivot_parent.starting_job.analyzable.name
        else:
            logger.warning(
                f"Job #{self.job_id}: Analyzer {self.analyzer_name} should be ran from PhishingAnalysis playbook."
            )
        if self.target_site:
            logger.info(f"Job #{self.job_id}: Extracted {self.target_site} from parent job.")
        else:
            logger.info(
                f"Job #{self.job_id}: Target site from parent job not found! Proceeding with only source code."
            )

        # generate fake values for each mapping
        fake = Faker()
        # mapping between name attribute of text <input>
        # and their corresponding fake values
        self._name_text_input_mapping: {tuple: str} = {
            tuple(self.name_matching): fake.user_name(),
            tuple(self.cc_matching): fake.credit_card_number(),
            tuple(self.pin_matching): str(fake.random.randint(10000, 100000)),
            tuple(self.cvv_matching): fake.credit_card_security_code(),
            tuple(self.expiration_date_matching): fake.credit_card_expire(
                start=date.today(),
                end=date.today() + timedelta(days=fake.random.randint(1, 1000)),
                date_format="%m/%y",
            ),
        }
        logger.info(f"Generated name text input mapping {self._name_text_input_mapping}")
        self.FAKE_EMAIL_INPUT: str = fake.email()
        logger.info(f"Generated fake email input {self.FAKE_EMAIL_INPUT}")
        self.FAKE_PASSWORD_INPUT: str = fake.password(
            length=16,
            special_chars=True,
            digits=True,
            upper_case=True,
            lower_case=True,
        )
        logger.info(f"Generated fake password input {self.FAKE_PASSWORD_INPUT}")
        self.FAKE_TEL_INPUT: str = fake.phone_number()
        logger.info(f"Generated fake tel input {self.FAKE_TEL_INPUT}")

        # extract and decode source code from file
        self.html_source_code = self.read_file_bytes()
        if self.html_source_code:
            logger.debug(f"Job #{self.job_id}: {self.html_source_code=}")
            try:
                self.html_source_code = self.html_source_code.decode("utf-8")
            except UnicodeDecodeError as e:
                logger.warning(
                    f"Job #{self.job_id}: Error during HTML source page decoding: {e}\nTrying to fix the error..."
                )
                self.html_source_code = self.html_source_code.decode("utf-8", errors="replace")
            else:
                logger.info(f"Job #{self.job_id}: Extracted html source code from pivot.")
        else:
            raise ValueError("Failed to extract source code from pivot!")

        # recover=True tries to read not well-formed HTML
        html_parser = HTMLParser(recover=True, no_network=True)
        self.parsed_page = document_fromstring(self.html_source_code, parser=html_parser)

    def search_phishing_forms_xpath(self) -> []:
        # extract using a custom XPath selector if set
        return (
            xpath_query_on_page(self.parsed_page, self.xpath_form_selector)
            if self.xpath_form_selector
            else []
        )

    def identify_text_input(self, input_name: str) -> str:
        for names, fake_value in self._name_text_input_mapping.items():
            if input_name in names:
                return fake_value

    @staticmethod
    def extract_action_attribute(base_site: str, form) -> str:
        # we always return an URL to prevent MissingSchema error in request
        if "://" not in base_site:
            # if target site is a domain add a temporary default
            # schema so we can use urljoin as if it was an url
            base_site = "https://" + base_site
        form_action: str = form.get("action", None)
        if not form_action:
            logger.info(f"'action' attribute not found in form. Defaulting to {base_site=}")
            return base_site

        form_action = urljoin(base_site, form_action)
        if "://" not in form_action:
            form_action = "https://" + form_action
        logger.info(f"Extracted action to post data to: {form_action}")

        return form_action

    def compile_form_field(self, form) -> dict:
        result: {} = {}

        for element in form.findall(".//input"):
            input_type: str = element.get("type", None)
            input_name: str = element.get("name", None)
            input_value: str = element.get("value", None)
            value_to_set: str = ""
            match input_type.lower():
                case "hidden":
                    logger.info(
                        f"Job #{self.job_id}: Found hidden input tag with {input_name=} and {input_value=}"
                    )
                    value_to_set = input_value

                case "text":
                    value_to_set = self.identify_text_input(input_name)
                case "password":
                    value_to_set = self.FAKE_PASSWORD_INPUT
                case "tel":
                    value_to_set = self.FAKE_TEL_INPUT
                case "email":
                    value_to_set = self.FAKE_EMAIL_INPUT
                case _:
                    logger.info(f"Job #{self.job_id}: {input_type.lower()} is not supported yet!")

            logger.info(f"Job #{self.job_id}: Sending value {value_to_set} for {input_name=}")
            result.setdefault(input_name, value_to_set)
        return result

    def perform_request_to_form(self, form) -> Response:
        params = self.compile_form_field(form)
        dest_url = self.extract_action_attribute(self.target_site, form)
        logger.info(f"Job #{self.job_id}: Sending {params=} to submit url {dest_url}")
        headers = {
            "User-Agent": self.user_agent,
        }
        response = requests.post(
            url=dest_url,
            data=params,
            headers=headers,
            proxies=(
                {"http": self.proxy_address, "https": self.proxy_address} if self.proxy_address else None
            ),
        )
        logger.info(f"Request headers: {response.request.headers}")
        return response

    @staticmethod
    def handle_3xx_response(response: Response) -> [str]:
        result: [] = []
        # extract all redirection history
        for history in response.history:
            logger.info(f"Extracting 3xx {response.status_code} HTTP response with url {history.request.url}")
            result.append(history.request.url)
        return result

    @staticmethod
    def handle_2xx_response(response: Response) -> str:
        logger.info(f"Extracting 2xx {response.status_code} response with url {response.request.url}")
        return response.request.url

    def is_js_used_in_page(self) -> bool:
        js_tag: [] = xpath_query_on_page(self.parsed_page, self.xpath_js_selector)
        if js_tag:
            logger.info(f"Job #{self.job_id}: Found script tag: {js_tag}")
        return bool(js_tag)

    def analyze_responses(self, responses: [Response]) -> ([], []):
        success_result: [] = []
        redirect_result: [] = []
        for response in responses:
            logger.info(f"Response headers for {response.url}: {response.headers}")
            try:
                # handle 4xx and 5xx
                response.raise_for_status()
            except HTTPError as e:
                message = f"Error during request to {response.request.url}: {e}"
                logger.error(f"Job #{self.job_id}:" + message)
                self.report.errors.append(message)
            else:
                if response.history:
                    redirect_result.extend(self.handle_3xx_response(response))

                success_result.append(self.handle_2xx_response(response))
        self.report.save()

        return success_result, redirect_result

    def run(self) -> dict:
        result: {} = {}
        if not (forms := xpath_query_on_page(self.parsed_page, self.xpath_form_selector)):
            message = (
                f"Form not found in {self.target_site=} with "
                f"{self.xpath_form_selector=}! This could mean that the XPath"
                f" selector requires some tuning."
            )
            logger.warning(f"Job #{self.job_id}: " + message)
            self.report.errors.append(message)
            self.report.save()
        logger.info(f"Job #{self.job_id}: Found {len(forms)} forms in page {self.target_site}")

        responses: [Response] = []
        for form in forms:
            responses.append(self.perform_request_to_form(form))

        success_result, redirect_result = self.analyze_responses(responses)
        result.setdefault("extracted_urls", success_result)
        result.setdefault("redirection_urls", redirect_result)
        result.setdefault("has_javascript", self.is_js_used_in_page())
        return result

    def update(self) -> bool:
        pass
