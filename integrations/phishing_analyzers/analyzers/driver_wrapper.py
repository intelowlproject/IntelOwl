import functools
import logging
import os
from typing import Iterator

from selenium.common import WebDriverException
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.wait import WebDriverWait
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


def driver_exception_handler(func):
    @functools.wraps(func)
    def handle_exception(self, *args, **kwargs):
        # if url is set the action should be "navigate"
        url = kwargs.get("url", "")
        try:
            return func(self, *args, **kwargs)
        except WebDriverException as e:
            logger.error(
                f"Error while performing {func.__name__}"
                f"{' for url=' + url if func.__name__ == 'navigate' else ''}: {e}"
            )
            # default is 5
            self.restart(motivation=func.__name__, timeout_wait_page=5)
            func(self, *args, **kwargs)

    return handle_exception


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
            # https://github.com/wkeeling/selenium-wire/issues/220#issuecomment-794308386
            # config to have local seleniumwire proxy compatible with another proxy
            "addr": "0.0.0.0",  # nosec B104 # where selenium-wire proxy will run
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
        options.add_argument("--ignore-certificate-errors")
        options.add_argument(f"--window-size={window_width},{window_height}")
        # traffic must go back to host running selenium-wire
        options.add_argument("--proxy-server=http://phishing_analyzers:7007")
        driver = Remote(
            command_executor="http://selenium-hub:4444/wd/hub",
            options=options,
            seleniumwire_options=sw_options,
        )
        return driver

    def restart(self, motivation: str = "", timeout_wait_page: int = 0):
        logger.info(f"Restarting driver: {motivation=}")
        self._driver.quit()
        self._driver = self._init_driver(
            window_width=self.window_width, window_height=self.window_height
        )
        if self.last_url:
            logger.info(f"Navigating to {self.last_url} after driver has restarted")
            self.navigate(self.last_url, timeout_wait_page=timeout_wait_page)

    @driver_exception_handler
    def navigate(self, url: str = "", timeout_wait_page: int = 0):
        if not url:
            logger.error("Empty URL! Something's wrong!")
            return

        self.last_url = url
        logger.info(f"Navigating to {url=}")
        self._driver.get(url)
        # dinamically wait for page to load its content with a fallback
        # of `timeout_wait_page` seconds.
        # waiting to see if any visible input tag appears
        if timeout_wait_page:
            WebDriverWait(self._driver, timeout=timeout_wait_page).until(
                EC.visibility_of_any_elements_located((By.TAG_NAME, "input"))
            )

    @driver_exception_handler
    def get_page_source(self) -> str:
        logger.info(f"Extracting page source for url {self.last_url}")
        return self._driver.page_source

    @driver_exception_handler
    def get_current_url(self) -> str:
        logger.info("Extracting current URL of page")
        return self._driver.current_url

    @driver_exception_handler
    def get_base64_screenshot(self) -> str:
        logger.info(f"Extracting screenshot of page as base64 for url {self.last_url}")
        return self._driver.get_screenshot_as_base64()

    def iter_requests(self) -> Iterator[Request]:
        return self._driver.iter_requests()

    def get_har(self) -> str:
        return self._driver.har

    def quit(self):
        self._driver.quit()
