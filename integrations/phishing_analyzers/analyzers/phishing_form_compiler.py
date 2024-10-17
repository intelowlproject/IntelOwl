import base64
import datetime
import logging
import os
from argparse import ArgumentParser
from random import randint
from xml.etree.ElementTree import Element

import requests
from driver_wrapper import Proxy
from lxml import etree
from lxml.html import HtmlElement, document_fromstring
from requests import HTTPError, Response

LOG_NAME = "phishing_form_compiler"

# get flask-shell2http logger instance
logger = logging.getLogger(LOG_NAME)
# logger config
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
log_level = os.getenv("LOG_LEVEL", logging.INFO)
log_path = os.getenv("LOG_PATH", f"/var/log/intel_owl/{LOG_NAME}")
# create new file handlers, files are created if doesn't already exists
fh = logging.FileHandler(f"{log_path}/{LOG_NAME}.log")
fh.setFormatter(formatter)
fh.setLevel(log_level)
fh_err = logging.FileHandler(f"{log_path}/{LOG_NAME}_errors.log")
fh_err.setFormatter(formatter)
fh_err.setLevel(logging.ERROR)
# add the handlers to the logger
logger.addHandler(fh)
logger.addHandler(fh_err)
logger.setLevel(log_level)

# fake inputs to compile forms with
FAKE_USERNAME_INPUT: str = "fakeuser"
FAKE_EMAIL_INPUT: str = "fake@email.com"
FAKE_PASSWORD_INPUT: str = "Fakepassword123!"
FAKE_TEL_INPUT: str = "+393333333333"
FAKE_CARD_INPUT: str = "4111111111111111"
FAKE_CARD_EXPIRATION_INPUT: str = (
    datetime.date.today() + datetime.timedelta(days=randint(1, 1000))
).strftime("%m/%y")
FAKE_PIN_INPUT: str = "00000"
FAKE_CVV_INPUT: str = "000"


def search_phishing_forms_generic(page) -> list:
    # extract using standard forms() method
    # looking for <form> tags only on HtmlElement type
    if isinstance(page, HtmlElement):
        return page.forms()

    try:
        return HtmlElement(page).forms()
    except TypeError:
        logger.error(f"Page of type {type(page)} can't be converted to HtmlElement")
        return []


def search_phishing_forms_xpath(page, xpath_selector: str = "") -> list:
    # extract using a custom XPath selector if set
    return page.xpath(xpath_selector) if xpath_selector else []


def phishing_forms_exists(source: str, xpath_selector: str = "") -> list:
    # recover=True tries to read not well-formed HTML
    html_parser = etree.HTMLParser(recover=True)
    page = document_fromstring(source, parser=html_parser)
    return search_phishing_forms_xpath(
        page, xpath_selector
    )  # + search_phishing_forms_generic(page)


def identify_text_input(input_name: str) -> str:
    if input_name.lower() in [
        "username",
        "user",
        "name",
        "first-name",
        "last-name",
    ]:
        return FAKE_USERNAME_INPUT
    elif input_name.lower() in [
        "card",
        "card_number",
        "card-number",
        "cc",
        "cc-number",
    ]:
        return FAKE_CARD_INPUT
    elif input_name.lower() in [
        "pin",
    ]:
        return FAKE_PIN_INPUT
    elif input_name.lower() in ["cvv", "cvc"]:
        return FAKE_CVV_INPUT
    elif input_name.lower() in [
        "exp",
        "date",
        "expiration-date",
        "exp-date",
    ]:
        return FAKE_CARD_EXPIRATION_INPUT


def compile_form_field(form) -> (dict, str):
    result: {} = {}
    form_action: str = form.get("action", None)
    for element in form.findall(".//input"):
        input_type: str = element.get("type", None)
        input_name: str = element.get("name", None)
        input_value: str = element.get("value", None)
        value_to_set: str = ""
        match input_type.lower():
            case "hidden":
                logger.info(
                    f"Found hidden input tag with {input_name=} and {input_value=}"
                )
                value_to_set = input_value

            case "text":
                value_to_set = identify_text_input(input_name)
            case "password":
                value_to_set = FAKE_PASSWORD_INPUT
            case "tel":
                value_to_set = FAKE_TEL_INPUT
            case "email":
                value_to_set = FAKE_EMAIL_INPUT
            case _:
                logger.info(f"{input_type.lower()} is not supported yet!")
        logger.info(f"Sending value {value_to_set} for {input_name=}")
        result.setdefault(input_name, value_to_set)
    return result, form_action


def perform_request_to_form(
    target_site: str, form: Element, proxy_requests: Proxy = None
) -> Response:
    params, dest_url = compile_form_field(form)
    if not dest_url:
        dest_url = target_site

    logger.info(f"Sending {params=} to submit url {dest_url}")

    response = requests.post(
        url=dest_url, params=params, data=params, proxies=proxy_requests.for_requests
    )
    return response


def handle_3xx_response(response: Response) -> [str]:
    return [history.request.url for history in response.history]


def handle_2xx_response(response: Response) -> []:
    return response.request.url


def analyze_responses(responses: [Response]) -> []:
    result: [] = []
    for response in responses:
        try:
            # handle 4xx and 5xx
            response.raise_for_status()
        except HTTPError as e:
            message = f"Error during request to {response.request.url}: {e}"
            logger.error(message)
            return {"error": message}
        if response.history:
            # extract all redirection history
            result.extend(handle_3xx_response(response))
        # extract successful url
        result.append(handle_2xx_response(response))

    return result


def compile_phishing_form(
    target_site: str,
    source_code: str,
    xpath_selector: str = "",
    proxy_requests: Proxy = None,
) -> []:
    if not target_site or not source_code:
        return {"error": f"Missing {target_site} or {source_code}"}
    if not (forms := phishing_forms_exists(source_code, xpath_selector)):
        message = (
            f"Form not found in {target_site=} with {xpath_selector=}! "
            f"Manually check site to see if XPath selector requires some tuning."
        )
        logger.info(message)
        return {"error": message}

    logger.info(f"Found {len(forms)} forms in page {target_site}")
    responses: [Response] = []
    for form in forms:
        responses.append(
            perform_request_to_form(target_site, form, proxy_requests=proxy_requests)
        )

    print(analyze_responses(responses))


if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("--target_site", type=str, required=True)
    parser.add_argument("--source_code", type=str, required=True)
    parser.add_argument("--xpath_selector", type=str, required=False)
    parser.add_argument("--proxy_address", type=str, required=False)
    parser.add_argument("--proxy_protocol", type=str, required=False)
    parser.add_argument("--proxy_port", type=int, required=False)
    arguments = parser.parse_args()
    logger.info(f"Extracted arguments for {LOG_NAME}: {vars(arguments)}")

    proxy: Proxy = Proxy(
        proxy_address=arguments.proxy_address,
        proxy_protocol=arguments.proxy_protocol,
        proxy_port=arguments.proxy_port,
    )
    source_code_decoded = base64.b64decode(
        arguments.source_code.encode("utf-8")
    ).decode("utf-8")
    compile_phishing_form(
        target_site=arguments.target_site,
        source_code=source_code_decoded,
        xpath_selector=arguments.xpath_selector,
        proxy_requests=proxy,
    )
