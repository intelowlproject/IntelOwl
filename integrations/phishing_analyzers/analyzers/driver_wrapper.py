import logging
import os
from typing import Iterator

from selenium.common import WebDriverException
from seleniumwire.request import Request
from seleniumwire.webdriver import ChromeOptions, Remote

LOG_NAME = "driver_wrapper"

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


class DriverWrapper:
    def __init__(
        self,
        proxy_address: str = "",
        window_width: int = 1920,
        window_height: int = 1080,
    ):
        self.proxy: str = proxy_address
        self.window_width: int = window_width
        self.window_height: int = window_height
        self.last_url: str = ""
        self._driver: Remote = self._init_driver(self.window_width, self.window_height)

    def _init_driver(self, window_width: int, window_height: int) -> Remote:
        logger.info(f"Adding proxy with option: {self.proxy}")
        logger.info("Creating Chrome driver...")
        sw_options: {} = {
            "auto_config": False,  # Ensure this is set to False
            "enable_har": True,
            "addr": "phishing_analyzers",  # where selenium-wire proxy will run
            "port": 7007,
        }
        if self.proxy:
            sw_options["proxy"] = {"http": self.proxy, "https": self.proxy}

        options = ChromeOptions()
        # no_sandbox=True is a bad practice but it's almost the only way
        # to run chromium-based browsers in docker. browser is running
        # as unprivileged user and it's in a container: trade-off
        options.add_argument("--no-sandbox")
        options.add_argument("--headless=new")
        options.add_argument("ignore-certificate-errors")
        options.add_argument(f"--window-size={window_width},{window_height}")
        # traffic must go back to host running selenium-wire
        options.add_argument("--proxy-server={}".format("phishing_analyzers:7007"))
        driver = Remote(
            command_executor="http://selenium-hub:4444/wd/hub",
            options=options,
            seleniumwire_options=sw_options,
        )
        return driver

    def restart(self, motivation: str = ""):
        logger.info(f"Restarting driver: {motivation}")
        self._driver.quit()
        self._driver = self._init_driver(
            window_width=self.window_width, window_height=self.window_height
        )
        if self.last_url:
            self.navigate(self.last_url)

    def navigate(self, url: str):
        if not url:
            logger.error("Empty URL! Something's wrong!")
            return

        self.last_url = url
        try:
            self._driver.get(url)
        except WebDriverException as e:
            logger.error("navigate")
            logger.error(e)
            self.restart(motivation="navigate")

    @property
    def page_source(self) -> str:
        try:
            return self._driver.page_source
        except WebDriverException as e:
            logger.error("page_source")
            logger.error(e)
            self.restart(motivation="page_source")
            return self.page_source

    @property
    def current_url(self) -> str:
        try:
            return self._driver.current_url
        except WebDriverException as e:
            logger.error("current_url")
            logger.error(e)
            self.restart(motivation="current_url")
            return self.current_url

    @property
    def base64_screenshot(self) -> str:
        try:
            return self._driver.get_screenshot_as_base64()
        except WebDriverException as e:
            logger.error("base64_screenshot")
            logger.error(e)
            self.restart(motivation="base64_screenshot")
            return self.base64_screenshot

    def iter_requests(self) -> Iterator[Request]:
        return self._driver.iter_requests()

    def get_har(self) -> str:
        return self._driver.har

    def quit(self):
        self._driver.quit()
