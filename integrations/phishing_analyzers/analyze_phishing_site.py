from argparse import ArgumentParser, BooleanOptionalAction
from logging import getLogger

import undetected_chromedriver as uc
from selenium.common import WebDriverException
from selenium.webdriver.chrome.webdriver import WebDriver

logger = getLogger(__name__)


class Proxy:
    def __init__(
        self, proxy_protocol: str = "", proxy_address: str = "", proxy_port: int = 0
    ):
        self.protocol: str = proxy_protocol
        self.address: str = proxy_address
        self.port: int = proxy_port


class DriverWrapper:
    def __init__(
        self,
        proxy_protocol: str = "",
        proxy_address: str = "",
        proxy_port: int = 0,
        headless: bool = True,
    ):
        self.proxy: Proxy = Proxy(proxy_protocol, proxy_address, proxy_port)
        self.headless: bool = headless
        self.driver: WebDriver = self._init_driver(headless=self.headless)
        self.last_url: str = ""

    def _init_driver(self, headless: bool = True) -> WebDriver:
        logger.info("Starting adding options for proxy in driver")
        options: uc.ChromeOptions = uc.ChromeOptions()
        if self.proxy.address:
            options.add_argument(
                "--proxy-server="
                f"{self.proxy.protocol + '://' if self.proxy.address else ''}"
                f"{self.proxy.address}"
                f"{':' + str(self.proxy.port) if self.proxy.port else ''}"
            )
            options.add_argument(
                f'--host-resolver-rules="MAP * ~NOTFOUND, EXCLUDE {self.proxy.address}"'
            )
        if headless:
            options.add_argument("--headless=new")
        logger.info("Finished adding options for proxy in driver")
        return uc.Chrome(
            use_subprocess=False,
            browser_executable_path="/usr/bin/google-chrome",
            options=options,
        )

    def restart(self, motivation: str = ""):
        logger.info(f"Restarting driver: {motivation}")
        self.driver.quit()
        self.driver = self._init_driver(headless=self.headless)
        if self.last_url:
            self.navigate(self.last_url)

    def navigate(self, url: str):
        self.last_url = url
        try:
            self.driver.get(url)
        except WebDriverException:
            self.restart(motivation="navigate")

    @property
    def page_source(self) -> str:
        try:
            return self.driver.page_source
        except WebDriverException:
            self.restart(motivation="page_source")
            return self.page_source

    @property
    def current_url(self) -> str:
        try:
            return self.driver.current_url
        except WebDriverException:
            self.restart(motivation="current_url")
            return self.current_url


if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("--proxy_address", type=str, required=False)
    parser.add_argument("--proxy_protocol", type=str, required=False)
    parser.add_argument("--proxy_port", type=int, required=False)
    parser.add_argument("--headless", action=BooleanOptionalAction, required=False)
    arguments = parser.parse_args()
    driver = DriverWrapper(**vars(arguments))
