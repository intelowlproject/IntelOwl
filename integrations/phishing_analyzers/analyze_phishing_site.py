import json
import logging
import os
from argparse import ArgumentParser

from selenium.common import WebDriverException
from selenium.webdriver.chrome.webdriver import WebDriver
from seleniumbase import Driver

LOG_NAME = "analyze_phishing_site"

# get flask-shell2http logger instance
logger = logging.getLogger("analyze_phishing_site")
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


class Proxy:
    def __init__(
        self, proxy_protocol: str = "", proxy_address: str = "", proxy_port: int = 0
    ):
        self.protocol: str = proxy_protocol
        self.address: str = proxy_address
        self.port: int = proxy_port

    def __repr__(self):
        return (
            f"{self.protocol + '://' if self.address and self.protocol else ''}"
            f"{self.address}{':' + str(self.port) if self.port else ''}"
        )


# forse estendere il driver può permettere di usare questa classe come context manager.
# potrebbe essere un buon compromesso. da provare lunedì.
class DriverWrapper:
    def __init__(
        self,
        proxy_protocol: str = "",
        proxy_address: str = "",
        proxy_port: int = 0,
        **kwargs,
    ):
        self.proxy: Proxy = Proxy(proxy_protocol, proxy_address, proxy_port)
        self.driver: WebDriver = self._init_driver()
        self.last_url: str = ""

    def _init_driver(self) -> WebDriver:
        logger.info(f"Adding proxy with option: {self.proxy}")
        logger.info("Creating Chrome driver...")
        # no_sandbox=True sucks but it's almost the only way to run chromium-based
        # browsers in docker. browser is running as unprivileged user and
        # it's in a container: trade-off
        driver = Driver(
            headless=True,
            headless2=True,
            use_wire=True,
            no_sandbox=True,
            proxy=str(self.proxy) if self.proxy.address else None,
            proxy_bypass_list=str(self.proxy.address) if self.proxy.address else None,
        )
        # TODO: make window size a parameter
        driver.set_window_size(1920, 1080)
        return driver

    def restart(self, motivation: str = ""):
        logger.info(f"Restarting driver: {motivation}")
        self.driver.quit()
        self.driver = self._init_driver()
        if self.last_url:
            self.navigate(self.last_url)

    def navigate(self, url: str):
        if not url:
            logger.error("Empty URL! Something's wrong!")
            return

        self.last_url = url
        try:
            self.driver.get(url)
        except WebDriverException as e:
            logger.error("navigate")
            logger.error(e)
            self.restart(motivation="navigate")

    @property
    def page_source(self) -> str:
        try:
            return self.driver.page_source
        except WebDriverException as e:
            logger.error("page_source")
            logger.error(e)
            self.restart(motivation="page_source")
            return self.page_source

    @property
    def current_url(self) -> str:
        try:
            return self.driver.current_url
        except WebDriverException as e:
            logger.error("current_url")
            logger.error(e)
            self.restart(motivation="current_url")
            return self.current_url

    @property
    def base64_screenshot(self) -> str:
        try:
            return self.driver.get_screenshot_as_base64()
        except WebDriverException as e:
            logger.error("base64_screenshot")
            logger.error(e)
            self.restart(motivation="base64_screenshot")
            return self.base64_screenshot


def analyze_target(**kwargs):
    driver_wrapper = DriverWrapper(**kwargs)
    driver_wrapper.navigate(url=kwargs["target"])
    print(
        json.dumps(
            {
                "page_extraction": {
                    "page_source": driver_wrapper.page_source,
                    "page_view_base64": driver_wrapper.base64_screenshot,
                }
            }
        )
    )
    driver_wrapper.driver.quit()


if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("--target", type=str)
    parser.add_argument("--proxy_address", type=str, required=False)
    parser.add_argument("--proxy_protocol", type=str, required=False)
    parser.add_argument("--proxy_port", type=int, required=False)
    arguments = parser.parse_args()
    logger.info(vars(arguments))
    analyze_target(**vars(arguments))
