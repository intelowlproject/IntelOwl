import base64
import json
from argparse import ArgumentParser

from driver_wrapper_playwright import PlaywrightDriverWrapper
from logging_setup import setup_file_logger
from playwright_request_serializer import dump_playwright_request

logger = setup_file_logger("extract_phishing_site_playwright")


def extract_driver_result(driver_wrapper: PlaywrightDriverWrapper) -> dict:
    logger.info("Extracting Playwright driver result...")
    driver_result: dict = {
        "page_source": base64.b64encode(
            driver_wrapper.get_page_source().encode("utf-8")
        ).decode("utf-8"),
        "page_screenshot_base64": driver_wrapper.get_base64_screenshot(),
        "page_http_traffic": [
            dump_playwright_request(entry)
            for entry in driver_wrapper.iter_requests()
        ],
        "page_http_har": driver_wrapper.get_har(),
    }
    logger.info("Finished extracting Playwright driver result")
    logger.debug(f"{driver_result=}")
    return driver_result


def analyze_target(
    target_url: str,
    proxy_address: str = "",
    window_width: int = 1920,
    window_height: int = 1080,
    user_agent: str = PlaywrightDriverWrapper.DEFAULT_USER_AGENT,
):
    driver_wrapper = None
    try:
        driver_wrapper = PlaywrightDriverWrapper(
            proxy_address=proxy_address,
            window_width=window_width,
            window_height=window_height,
            user_agent=user_agent,
        )
        driver_wrapper.navigate(url=target_url, timeout_wait_page=5)

        result: str = json.dumps(extract_driver_result(driver_wrapper), default=str)
        logger.debug(f"JSON dump of Playwright driver {result=}")

        print(result)
    except Exception as e:
        logger.exception(
            f"Exception during Playwright analysis of target website {target_url}: {e}"
        )
    finally:
        if driver_wrapper:
            driver_wrapper.quit()


if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("--target", type=str, required=True)
    parser.add_argument("--proxy_address", type=str, required=False, default="")
    parser.add_argument("--window_width", type=int, required=False, default=1920)
    parser.add_argument("--window_height", type=int, required=False, default=1080)
    parser.add_argument(
        "--user_agent", type=str, required=False,
        default=PlaywrightDriverWrapper.DEFAULT_USER_AGENT,
    )
    arguments = parser.parse_args()
    logger.info(f"Extracted arguments: {vars(arguments)}")

    analyze_target(
        target_url=arguments.target,
        proxy_address=arguments.proxy_address,
        window_width=arguments.window_width,
        window_height=arguments.window_height,
        user_agent=arguments.user_agent,
    )
