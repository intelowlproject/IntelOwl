import logging
import os
from argparse import ArgumentParser
from xml.etree.ElementTree import Element

import elementpath
from lxml import etree

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


def phishing_forms_exists(source: str, xpath_selector: str) -> list:
    # recover=True tries to read not well-formed HTML
    html_parser = etree.HTMLParser(recover=True)
    page = etree.fromstring(source, parser=html_parser)
    return elementpath.select(page, xpath_selector)


def perform_request_to_form(form: Element) -> dict:
    pass


def compile_phishing_form(**kwargs):
    target_site: str = kwargs["target_site"]
    source_code: str = kwargs["source_code"]
    xpath_selector: str = kwargs["xpath_selector"]

    if not (forms := phishing_forms_exists(source_code, xpath_selector)):
        logger.info(
            f"Form not found in {target_site=} with {xpath_selector=}! "
            f"Manually check site to see if XPath selector requires some tuning."
        )

    for form in forms:
        perform_request_to_form(form)


if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("--target_site", type=str)
    parser.add_argument("--source_code", type=str)
    parser.add_argument("--xpath_selector", type=str)
    # TODO: handle proxy from this analyzer
    # parser.add_argument("--proxy_address", type=str, required=False)
    # parser.add_argument("--proxy_protocol", type=str, required=False)
    # parser.add_argument("--proxy_port", type=int, required=False)
    arguments = parser.parse_args()
    logger.info(f"Extracted arguments for {LOG_NAME}: {vars(arguments)}")
    compile_phishing_form(**vars(arguments))
