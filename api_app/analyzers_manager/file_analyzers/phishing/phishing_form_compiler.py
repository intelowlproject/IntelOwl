import logging
from datetime import date, timedelta
from typing import Dict

import requests
from faker import Faker
from lxml.etree import HTMLParser
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
            self.target_site = self._job.pivot_parent.starting_job.observable_name
        else:
            logger.warning(
                f"Job #{self.job_id}: Analyzer {self.analyzer_name} should be ran from PhishingAnalysis playbook."
            )
        if self.target_site:
            logger.info(
                f"Job #{self.job_id}: Extracted {self.target_site} from parent job."
            )
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
        logger.info(
            f"Generated name text input mapping {self._name_text_input_mapping}"
        )
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
                self.html_source_code = self.html_source_code.decode(
                    "utf-8", errors="replace"
                )
            else:
                logger.info(
                    f"Job #{self.job_id}: Extracted html source code from pivot."
                )
        else:
            raise ValueError("Failed to extract source code from pivot!")

        # recover=True tries to read not well-formed HTML
        html_parser = HTMLParser(recover=True, no_network=True)
        self.parsed_page = document_fromstring(
            self.html_source_code, parser=html_parser
        )

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

    def compile_form_field(self, form) -> (dict, str):
        result: {} = {}
        # setting default to page itself if action is not specified
        if not (form_action := form.get("action", None)):
            form_action = self.target_site
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
                    logger.info(
                        f"Job #{self.job_id}: {input_type.lower()} is not supported yet!"
                    )

            logger.info(
                f"Job #{self.job_id}: Sending value {value_to_set} for {input_name=}"
            )
            result.setdefault(input_name, value_to_set)
        return result, form_action

    def perform_request_to_form(self, form) -> Response:
        params, dest_url = self.compile_form_field(form)
        logger.info(f"Job #{self.job_id}: Sending {params=} to submit url {dest_url}")
        return requests.post(
            url=dest_url,
            data=params,
            proxies=(
                {"http": self.proxy_address, "https": self.proxy_address}
                if self.proxy_address
                else None
            ),
        )

    @staticmethod
    def handle_3xx_response(response: Response) -> [str]:
        # extract all redirection history
        return [history.request.url for history in response.history]

    @staticmethod
    def handle_2xx_response(response: Response) -> str:
        return response.request.url

    def is_js_used_in_page(self) -> bool:
        js_tag: [] = xpath_query_on_page(self.parsed_page, self.xpath_js_selector)
        if js_tag:
            logger.info(f"Job #{self.job_id}: Found script tag: {js_tag}")
        return bool(js_tag)

    def analyze_responses(self, responses: [Response]) -> {}:
        result: [] = []
        for response in responses:
            try:
                # handle 4xx and 5xx
                response.raise_for_status()
            except HTTPError as e:
                message = f"Error during request to {response.request.url}: {e}"
                logger.error(f"Job #{self.job_id}:" + message)
                self.report.errors.append(message)
            else:
                if response.history:
                    result.extend(self.handle_3xx_response(response))

                result.append(self.handle_2xx_response(response))
        self.report.save()

        return result

    def run(self) -> dict:
        result: {} = {}
        if not (
            forms := xpath_query_on_page(self.parsed_page, self.xpath_form_selector)
        ):
            message = (
                f"Form not found in {self.target_site=} with "
                f"{self.xpath_form_selector=}! This could mean that the XPath"
                f" selector requires some tuning."
            )
            logger.warning(f"Job #{self.job_id}: " + message)
            self.report.errors.append(message)
            self.report.save()
        logger.info(
            f"Job #{self.job_id}: Found {len(forms)} forms in page {self.target_site}"
        )

        responses: [Response] = []
        for form in forms:
            responses.append(self.perform_request_to_form(form))

        result.setdefault("extracted_urls", self.analyze_responses(responses))
        result.setdefault("has_javascript", self.is_js_used_in_page())
        return result

    def update(self) -> bool:
        pass
