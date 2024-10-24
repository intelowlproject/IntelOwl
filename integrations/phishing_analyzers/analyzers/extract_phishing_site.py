import base64
import json
import logging
import os
from argparse import ArgumentParser

from driver_wrapper import DriverWrapper
from seleniumwire_request_serializer import dump_seleniumwire_requests

LOG_NAME = "extract_phishing_site"

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


def extract_driver_result(driver_wrapper: DriverWrapper) -> dict:
    return {
        "page_source": base64.b64encode(
            driver_wrapper.page_source.encode("utf-8")
        ).decode("ascii"),
        "page_screenshot_base64": driver_wrapper.base64_screenshot,
        "page_http_traffic": [
            dump_seleniumwire_requests(request)
            for request in driver_wrapper.iter_requests()
        ],
        "page_http_har": driver_wrapper.driver.har,
    }


def analyze_target(
    target_url: str,
    proxy_address: str,
    window_width: int = 1920,
    window_height: int = 1080,
):
    # TODO: handle the concept of open tabs to avoid possible memory overuse
    driver_wrapper = DriverWrapper(
        proxy_address=proxy_address,
        window_width=window_width,
        window_height=window_height,
    )
    driver_wrapper.navigate(url=target_url)

    result: str = json.dumps(extract_driver_result(driver_wrapper), default=str)
    print(result)

    driver_wrapper.quit()


if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("--target", type=str, required=True)
    parser.add_argument("--proxy_address", type=str, required=False)
    parser.add_argument("--window_width", type=int, required=False)
    parser.add_argument("--window_height", type=int, required=False)
    arguments = parser.parse_args()
    logger.info(f"Extracted arguments for {LOG_NAME}: {vars(arguments)}")

    analyze_target(
        target_url=arguments.target,
        proxy_address=arguments.proxy_address,
        window_width=arguments.window_width,
        window_height=arguments.window_height,
    )
