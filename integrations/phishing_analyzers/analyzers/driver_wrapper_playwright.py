import base64
import functools
import json
import os
import tempfile
import time
from collections.abc import Iterator
from datetime import datetime, timezone

from logging_setup import setup_file_logger
from playwright.sync_api import (
    Browser,
    BrowserContext,
    Page,
    Request,
    Response,
    WebSocket,
    sync_playwright,
)
from playwright.sync_api import (
    Error as PlaywrightError,
)
from playwright.sync_api import (
    TimeoutError as PlaywrightTimeoutError,
)

logger = setup_file_logger("driver_wrapper_playwright")


def _utcnow_str() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d, %H:%M:%S.%f")


def _get_post_body(request: Request) -> bytes | None:
    try:
        return request.post_data_buffer
    except Exception:
        return None


def _build_cert_info(security: dict | None) -> dict:
    if not security:
        return {}
    return {
        "subject": security.get("subjectName", ""),
        "issuer": security.get("issuer", ""),
        "valid_from": security.get("validFrom", ""),
        "valid_to": security.get("validTo", ""),
        "protocol": security.get("protocol", ""),
    }


def _build_request_entry(
    request: Request,
    post_body: bytes | None,
    response: dict | None = None,
) -> dict:
    return {
        "id": id(request),
        "method": request.method,
        "url": request.url,
        "headers": dict(request.headers or {}),
        "body": post_body or b"",
        "date": _utcnow_str(),
        "resource_type": request.resource_type,
        "redirected_from": (request.redirected_from.url if request.redirected_from else None),
        "redirected_to": (request.redirected_to.url if request.redirected_to else None),
        "ws_messages": [],
        "cert": {},
        "response": response,
    }


def playwright_exception_handler(func):
    @functools.wraps(func)
    def handle_exception(self, *args, **kwargs):
        url = kwargs.get("url", "")
        try:
            return func(self, *args, **kwargs)
        except PlaywrightError as e:
            logger.exception(
                f"PlaywrightError while performing {func.__name__}"
                f"{' for url=' + url if func.__name__ == 'navigate' else ''}: {e}"
            )
            self.restart(motivation=func.__name__, timeout_wait_page=5)
            return func(self, *args, **kwargs)

    return handle_exception


class PlaywrightDriverWrapper:
    DEFAULT_USER_AGENT = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/131.0.0.0 Safari/537.3"
    )

    def __init__(
        self,
        proxy_address: str = "",
        window_width: int = 1920,
        window_height: int = 1080,
        user_agent: str = DEFAULT_USER_AGENT,
    ):
        self.proxy: str = proxy_address
        self.window_width: int = window_width
        self.window_height: int = window_height
        self.user_agent: str = user_agent
        self.last_url: str = ""

        self._captured_requests: list[dict] = []
        self._har_path: str = ""

        self._playwright_ctx = None
        self._browser: Browser | None = None
        self._context: BrowserContext | None = None
        self._page: Page | None = None

        self._init_driver()

    def _build_launch_kwargs(self) -> dict:
        kwargs = {
            "headless": True,
            "args": [
                "--no-sandbox",
                "--ignore-certificate-errors",
                f"--window-size={self.window_width},{self.window_height}",
            ],
        }
        if self.proxy:
            kwargs["proxy"] = {"server": self.proxy}
        return kwargs

    def _reset_state(self):
        self._captured_requests = []

    def _create_context_and_page(self):
        # Use a temp file for built-in HAR recording
        _har_tmp = tempfile.NamedTemporaryFile(suffix=".har", delete=False)
        self._har_path = _har_tmp.name
        _har_tmp.close()
        self._context = self._browser.new_context(
            viewport={"width": self.window_width, "height": self.window_height},
            user_agent=self.user_agent,
            ignore_https_errors=True,
            record_har_path=self._har_path,
            record_har_content="embed",
        )
        self._reset_state()
        self._page = self._context.new_page()
        self._attach_network_listeners(self._page)

    def _close_browser(self):
        try:
            if self._page:
                self._page.close()
            if self._context:
                self._context.close()
            if self._browser:
                self._browser.close()
        except PlaywrightError as e:
            logger.warning(f"Error while closing browser: {e}")

    def _init_driver(self):
        logger.info(f"Initialising Playwright Chromium driver (proxy={self.proxy!r})")
        self._playwright_ctx = sync_playwright().start()
        self._browser = self._playwright_ctx.chromium.launch(**self._build_launch_kwargs())
        self._create_context_and_page()
        logger.info("Playwright driver initialised successfully")

    def _attach_network_listeners(self, page: Page):
        def on_request_finished(request: Request):
            try:
                try:
                    response: Response | None = request.response()
                except Exception:
                    response = None

                resp_dict = None
                cert = {}
                if response:
                    try:
                        body: bytes = response.body()
                        if body is None:
                            body = b""
                    except Exception:
                        body = b""

                    # Use Playwright's built-in security_details() for TLS cert info
                    cert = _build_cert_info(response.security_details())

                    resp_dict = {
                        "status_code": response.status,
                        "reason": response.status_text or "",
                        "headers": dict(response.headers or {}),
                        "body": body,
                        "date": _utcnow_str(),
                        "cert": cert,
                    }

                entry = _build_request_entry(request, _get_post_body(request), resp_dict)
                entry["cert"] = cert
                self._captured_requests.append(entry)
            except Exception as e:
                logger.warning(f"on_request_finished handler error: {e}")

        def on_request_failed(request: Request):
            try:
                self._captured_requests.append(_build_request_entry(request, _get_post_body(request)))
            except Exception as e:
                logger.warning(f"on_request_failed handler error: {e}")

        def on_websocket(ws: WebSocket):
            try:
                ws_entry: dict = {
                    "id": id(ws),
                    "method": "WEBSOCKET",
                    "url": ws.url,
                    "headers": {},
                    "body": b"",
                    "date": _utcnow_str(),
                    "resource_type": "websocket",
                    "redirected_from": None,
                    "redirected_to": None,
                    "ws_messages": [],
                    "cert": {},
                    "response": None,
                }

                def _on_frame(payload, from_client):
                    try:
                        raw = payload if isinstance(payload, bytes) else (str(payload or "")).encode()
                        ws_entry["ws_messages"].append(
                            {"from_client": from_client, "content": raw, "date": _utcnow_str()}
                        )
                    except Exception as e:
                        logger.warning(f"ws frame handler error: {e}")

                def _on_close():
                    try:
                        self._captured_requests.append(ws_entry)
                    except Exception as e:
                        logger.warning(f"ws _on_close handler error: {e}")

                ws.on("framesent", lambda p: _on_frame(p, True))
                ws.on("framereceived", lambda p: _on_frame(p, False))
                ws.on("close", _on_close)
            except Exception as e:
                logger.warning(f"on_websocket handler error: {e}")

        page.on("requestfinished", on_request_finished)
        page.on("requestfailed", on_request_failed)
        page.on("websocket", on_websocket)

    def restart(self, motivation: str = "", timeout_wait_page: int = 0):
        logger.info(f"Restarting Playwright driver: {motivation=}")
        self._close_browser()
        self._browser = self._playwright_ctx.chromium.launch(**self._build_launch_kwargs())
        self._create_context_and_page()

        if self.last_url:
            logger.info(f"Re-navigating to {self.last_url} after restart")
            self.navigate(self.last_url, timeout_wait_page=timeout_wait_page)

    @playwright_exception_handler
    def navigate(self, url: str = "", timeout_wait_page: int = 0):
        if not url:
            logger.error("Empty URL! Something's wrong!")
            return

        self.last_url = url
        logger.info(f"Navigating to {url=}")
        try:
            self._page.goto(url, wait_until="networkidle", timeout=30_000)
        except PlaywrightTimeoutError:
            logger.warning(f"networkidle timeout exceeded for {url}; proceeding with whatever loaded.")

        if timeout_wait_page:
            try:
                self._page.wait_for_selector("input", state="visible", timeout=timeout_wait_page * 1_000)
            except PlaywrightTimeoutError:
                logger.info("Timeout waiting for input tag to appear — page may not have an input field.")

    @playwright_exception_handler
    def get_page_source(self) -> str:
        logger.info(f"Extracting page source for url {self.last_url}")
        for attempt in range(3):
            try:
                return self._page.content()
            except PlaywrightError as e:
                logger.warning(
                    f"Failed to extract page source (attempt {attempt + 1}/3) for {self.last_url}: {e}"
                )
                try:
                    self._page.wait_for_load_state("domcontentloaded", timeout=5_000)
                except PlaywrightError:
                    pass
                time.sleep(0.5)
        return ""

    @playwright_exception_handler
    def get_current_url(self) -> str:
        logger.info("Extracting current URL of page")
        return self._page.url

    @playwright_exception_handler
    def get_base64_screenshot(self) -> str:
        logger.info(f"Taking screenshot for url {self.last_url}")
        screenshot_bytes: bytes = self._page.screenshot(full_page=True)
        return base64.b64encode(screenshot_bytes).decode("utf-8")

    def iter_requests(self) -> Iterator[dict]:
        return iter(self._captured_requests)

    def get_har(self) -> str:
        # Flush the HAR to disk by closing the page (context stays open)
        try:
            if self._page:
                self._page.close()
                self._page = None
        except PlaywrightError:
            pass

        # Route HAR through context close which writes the file
        try:
            if self._context:
                self._context.close()
                self._context = None
        except PlaywrightError:
            pass

        try:
            with open(self._har_path, "r", encoding="utf-8") as f:
                return f.read()
        except (OSError, FileNotFoundError):
            logger.warning("HAR file not found; returning empty HAR")
            return json.dumps(
                {
                    "log": {
                        "version": "1.2",
                        "creator": {"name": "IntelOwl-Playwright", "version": "1.0"},
                        "entries": [],
                    }
                }
            )

    def close(self):
        logger.info("Closing Playwright page")
        if self._page:
            self._page.close()

    def quit(self):
        logger.info("Quitting Playwright browser")
        try:
            self._close_browser()
        finally:
            if self._playwright_ctx:
                self._playwright_ctx.stop()
            # Clean up temp HAR file
            try:
                if self._har_path and os.path.exists(self._har_path):
                    os.unlink(self._har_path)
            except OSError:
                pass
