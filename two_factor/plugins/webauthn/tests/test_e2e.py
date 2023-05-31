try:
    from selenium import webdriver
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.webdriver.support.ui import WebDriverWait
except ImportError:
    webdriver = None

from unittest import skipUnless
from urllib.parse import urljoin

from django.contrib.staticfiles.testing import StaticLiveServerTestCase
from django.urls import reverse

from tests.utils import UserMixin
from two_factor.utils import default_device

try:
    import webauthn
except ImportError:
    webauthn = None

try:
    from webdriver_manager.chrome import ChromeDriverManager
    from webdriver_manager.utils import ChromeType
except ImportError:
    ChromeDriverManager = None


@skipUnless(webdriver, "package selenium is not present")
@skipUnless(ChromeDriverManager, "package webdriver-manager is not present")
@skipUnless(webauthn, "package webauthn is not present")
class E2ETests(UserMixin, StaticLiveServerTestCase):
    port = 8000
    timeout = 8

    def setUp(self):
        self.base_url = f"http://{self.host}:{self.port}"
        self.login_url = urljoin(self.base_url, reverse("two_factor:login"))

        options = webdriver.ChromeOptions()
        options.add_argument("headless")
        try:
            driver = ChromeDriverManager()
        except ValueError:
            driver = ChromeDriverManager(chrome_type=ChromeType.CHROMIUM)
        self.webdriver = webdriver.Chrome(driver.install(), options=options)

        super().setUp()

    def tearDown(self):
        self.webdriver.quit()
        super().tearDown()

    def setup_virtual_authenticator(self):
        self.webdriver.execute_cdp_cmd("WebAuthn.enable", {})
        virtual_authenticator_options = {
            "protocol": "u2f",
            "transport": "usb",
        }
        self.virtual_authenticator = self.webdriver.execute_cdp_cmd(
            "WebAuthn.addVirtualAuthenticator",
            {"options": virtual_authenticator_options},
        )

    def wait_for_element(self, selector_type, element):
        return WebDriverWait(self.webdriver, self.timeout).until(
            EC.presence_of_element_located((selector_type, element))
        )

    def wait_for_url(self, url):
        WebDriverWait(self.webdriver, self.timeout).until(EC.url_to_be(url))

    def do_login(self):
        self.wait_for_url(self.login_url)

        username = self.webdriver.find_element(By.ID, "id_auth-username")
        username.clear()
        username.send_keys("bouke@example.com")

        password = self.webdriver.find_element(By.ID, "id_auth-password")
        password.clear()
        password.send_keys("secret")

        button_next = self.webdriver.find_element(By.XPATH, "//button[@type='submit']")
        button_next.click()

    def register_authenticator(self):
        self.wait_for_url(urljoin(self.base_url, reverse("two_factor:setup")))
        self.webdriver.find_element(By.XPATH, "//button[@type='submit']").click()

        self.wait_for_element(By.XPATH, "//input[@value='webauthn']").click()
        self.webdriver.find_element(
            By.XPATH, "//button[@class='btn btn-primary']"
        ).click()

    def test_webauthn_attestation_and_assertion(self):
        user = self.create_user()
        self.setup_virtual_authenticator()

        self.webdriver.get(self.login_url)
        self.do_login()

        # register the webauthn authenticator as a second factor
        self.register_authenticator()
        self.wait_for_url(urljoin(self.base_url, reverse("two_factor:setup_complete")))

        # log out, log in
        self.webdriver.get(
            urljoin(
                self.base_url,
                reverse("logout") + "?next=" + reverse("two_factor:login"),
            )
        )
        self.do_login()
        self.wait_for_element(
            By.XPATH,
            "//p[contains(text(), 'Primary method: Authenticate using a \
                                  ' WebAuthn-compatible device')]",
        )

        # try registering the same authenticator and fail
        # (have to modify the existing authenticator first,
        # so it's no longer the default one)
        authenticator = default_device(user)
        self.assertIsNotNone(authenticator)
        authenticator.name = "not default anymore"
        authenticator.save()

        self.webdriver.get(urljoin(self.base_url, reverse("two_factor:setup")))
        self.register_authenticator()
        self.wait_for_element(By.XPATH, "//p[@class='text-danger']")
