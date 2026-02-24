import base64
import functools
import json
import time
from collections.abc import Iterator
from datetime import datetime, timezone
from urllib.parse import parse_qsl, urlparse

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

        self._cdp_security_by_url: dict[str, dict] = {}
        self._cdp_extra_requests: list[dict] = []
        self._cdp_inflight: dict[str, dict] = {}
        self._cdp_session = None
        self._captured_keys: set[tuple[str, str]] = set()

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
        self._cdp_security_by_url = {}
        self._cdp_extra_requests = []
        self._cdp_inflight = {}
        self._cdp_session = None
        self._captured_keys = set()

    def _create_context_and_page(self):
        self._context = self._browser.new_context(
            viewport={"width": self.window_width, "height": self.window_height},
            user_agent=self.user_agent,
            ignore_https_errors=True,
        )
        self._reset_state()
        self._page = self._context.new_page()
        self._attach_network_listeners(self._page)
        self._attach_cdp_listeners(self._page)

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
                if response:
                    try:
                        body: bytes = response.body()
                        if body is None:
                            body = b""
                    except Exception:
                        body = b""
                    resp_dict = {
                        "status_code": response.status,
                        "reason": response.status_text or "",
                        "headers": dict(response.headers or {}),
                        "body": body,
                        "date": _utcnow_str(),
                        "cert": {},
                    }

                self._captured_requests.append(
                    _build_request_entry(request, _get_post_body(request), resp_dict)
                )
                self._captured_keys.add((request.url, request.method))
            except Exception as e:
                logger.warning(f"on_request_finished handler error: {e}")

        def on_request_failed(request: Request):
            try:
                self._captured_requests.append(_build_request_entry(request, _get_post_body(request)))
                self._captured_keys.add((request.url, request.method))
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

    def _attach_cdp_listeners(self, page: Page):
        try:
            cdp = self._context.new_cdp_session(page)
        except Exception as e:
            logger.warning(f"Could not create CDP session: {e}")
            return

        try:
            cdp.send(
                "Network.enable",
                {
                    "maxTotalBufferSize": 10 * 1024 * 1024,
                    "maxResourceBufferSize": 5 * 1024 * 1024,
                },
            )
        except Exception as e:
            logger.warning(f"Could not enable CDP Network domain: {e}")
            return

        self._cdp_session = cdp

        def on_cdp_request(params: dict):
            try:
                req_id = params.get("requestId", "")
                req = params.get("request", {})
                redirect_resp = params.get("redirectResponse")

                if redirect_resp and req_id in self._cdp_inflight:
                    prev = self._cdp_inflight.pop(req_id)
                    prev["redirected_to"] = req.get("url", "")
                    _cdp_commit(prev)

                post_data = req.get("postData", "")
                entry: dict = {
                    "_cdp_source": True,
                    "_cdp_request_id": req_id,
                    "_cdp_type": params.get("type", ""),
                    "_cdp_initiator": params.get("initiator", {}),
                    "_cdp_from_cache": False,
                    "_cdp_blocked_reason": "",
                    "_cdp_error": "",
                    "id": req_id,
                    "method": req.get("method", "GET"),
                    "url": req.get("url", ""),
                    "headers": req.get("headers", {}),
                    "body": post_data.encode("utf-8", errors="replace") if post_data else b"",
                    "date": _utcnow_str(),
                    "resource_type": (params.get("type") or "").lower(),
                    "redirected_from": (req.get("url", "") if redirect_resp else None),
                    "redirected_to": None,
                    "ws_messages": [],
                    "cert": {},
                    "response": None,
                }
                self._cdp_inflight[req_id] = entry
            except Exception as e:
                logger.warning(f"CDP on_cdp_request error: {e}")

        def on_cdp_response(params: dict):
            try:
                req_id = params.get("requestId", "")
                resp = params.get("response", {})
                security = resp.get("securityDetails") or {}

                cert_info = {
                    "subject": security.get("subjectName", ""),
                    "issuer": security.get("issuer", ""),
                    "valid_from": security.get("validFrom", ""),
                    "valid_to": security.get("validTo", ""),
                    "protocol": security.get("protocol", ""),
                    "cipher": security.get("cipher", ""),
                    "san": security.get("sanList", []),
                }

                url = resp.get("url", "")
                if any(cert_info.values()):
                    self._cdp_security_by_url[url] = cert_info

                entry = self._cdp_inflight.get(req_id)
                if entry:
                    entry["cert"] = cert_info
                    entry["response"] = {
                        "status_code": resp.get("status", 0),
                        "reason": resp.get("statusText", ""),
                        "headers": resp.get("headers", {}),
                        "body": b"",
                        "date": _utcnow_str(),
                        "cert": cert_info,
                        "from_disk_cache": resp.get("fromDiskCache", False),
                        "from_service_worker": resp.get("fromServiceWorker", False),
                    }
            except Exception as e:
                logger.warning(f"CDP on_cdp_response error: {e}")

        def on_cdp_finished(params: dict):
            try:
                req_id = params.get("requestId", "")
                entry = self._cdp_inflight.pop(req_id, None)
                if not entry:
                    return
                if entry.get("response"):
                    try:
                        body_result = cdp.send("Network.getResponseBody", {"requestId": req_id})
                        raw = body_result.get("body", "")
                        if body_result.get("base64Encoded"):
                            entry["response"]["body"] = base64.b64decode(raw)
                        else:
                            entry["response"]["body"] = raw.encode("utf-8", errors="replace")
                    except Exception:
                        pass
                _cdp_commit(entry)
            except Exception as e:
                logger.warning(f"CDP on_cdp_finished error: {e}")

        def on_cdp_failed(params: dict):
            try:
                req_id = params.get("requestId", "")
                entry = self._cdp_inflight.pop(req_id, None)
                if not entry:
                    return
                entry["_cdp_blocked_reason"] = params.get("blockedReason", "")
                entry["_cdp_error"] = params.get("errorText", "")
                _cdp_commit(entry)
            except Exception as e:
                logger.warning(f"CDP on_cdp_failed error: {e}")

        def on_cdp_from_cache(params: dict):
            try:
                req_id = params.get("requestId", "")
                entry = self._cdp_inflight.get(req_id)
                if entry:
                    entry["_cdp_from_cache"] = True
            except Exception as e:
                logger.warning(f"CDP on_cdp_from_cache error: {e}")

        def _cdp_commit(entry: dict):
            url = entry.get("url", "")
            method = entry.get("method", "GET")
            cert = entry.get("cert") or {}

            if any(cert.values()):
                self._cdp_security_by_url[url] = cert

            already_captured = (url, method) in self._captured_keys
            if not already_captured:
                self._cdp_extra_requests.append(entry)

        cdp.on("Network.requestWillBeSent", on_cdp_request)
        cdp.on("Network.responseReceived", on_cdp_response)
        cdp.on("Network.loadingFinished", on_cdp_finished)
        cdp.on("Network.loadingFailed", on_cdp_failed)
        cdp.on("Network.requestServedFromCache", on_cdp_from_cache)
        logger.info("CDP Network listeners attached")

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
        results: list[dict] = []
        result_keys: set[tuple[str, str]] = set()
        for entry in self._captured_requests:
            url = entry.get("url", "")
            cert = self._cdp_security_by_url.get(url)
            if cert:
                entry = dict(entry)
                entry["cert"] = cert
                if isinstance(entry.get("response"), dict) and not entry["response"].get("cert"):
                    entry["response"] = dict(entry["response"])
                    entry["response"]["cert"] = cert
            results.append(entry)
            result_keys.add((url, entry.get("method", "GET")))

        for req_id, entry in list(self._cdp_inflight.items()):
            url = entry.get("url", "")
            method = entry.get("method", "GET")
            if (url, method) not in result_keys:
                self._cdp_extra_requests.append(entry)
        self._cdp_inflight.clear()

        results.extend(self._cdp_extra_requests)
        return iter(results)

    def get_har(self) -> str:
        def _headers_to_har(headers: dict) -> list[dict]:
            return [{"name": k, "value": v} for k, v in headers.items()]

        def _query_string(url: str) -> list[dict]:
            parsed = urlparse(url)
            return [{"name": k, "value": v} for k, v in parse_qsl(parsed.query)]

        entries = []
        all_requests = list(self._captured_requests) + list(self._cdp_extra_requests)
        for req in all_requests:
            response = req.get("response")
            resp_body: bytes = (response.get("body") or b"") if response else b""
            if not isinstance(resp_body, bytes):
                resp_body = str(resp_body).encode("utf-8", errors="replace")
            resp_mime = (
                (response.get("headers") or {}).get("content-type", "application/octet-stream")
                if response
                else "application/octet-stream"
            )

            entry = {
                "startedDateTime": req["date"],
                "time": -1,
                "request": {
                    "method": req["method"],
                    "url": req["url"],
                    "httpVersion": "HTTP/1.1",
                    "headers": _headers_to_har(req.get("headers", {})),
                    "queryString": _query_string(req["url"]),
                    "cookies": [],
                    "headersSize": -1,
                    "bodySize": len(req.get("body") or b""),
                    **(
                        {
                            "postData": {
                                "mimeType": (req.get("headers") or {}).get(
                                    "content-type", "application/octet-stream"
                                ),
                                "text": (
                                    req["body"].decode("utf-8", errors="replace")
                                    if isinstance(req.get("body"), bytes)
                                    else str(req.get("body") or "")
                                ),
                            }
                        }
                        if req.get("body")
                        else {}
                    ),
                },
                "response": (
                    {
                        "status": response.get("status_code", 0),
                        "statusText": response.get("reason", ""),
                        "httpVersion": "HTTP/1.1",
                        "headers": _headers_to_har(response.get("headers") or {}),
                        "cookies": [],
                        "content": {
                            "size": len(resp_body),
                            "mimeType": resp_mime,
                            "text": base64.b64encode(resp_body).decode("utf-8"),
                            "encoding": "base64",
                        },
                        "redirectURL": response.get("headers", {}).get("location", ""),
                        "headersSize": -1,
                        "bodySize": len(resp_body),
                    }
                    if response
                    else {
                        "status": 0,
                        "statusText": "",
                        "httpVersion": "HTTP/1.1",
                        "headers": [],
                        "cookies": [],
                        "content": {"size": 0, "mimeType": "application/octet-stream"},
                        "redirectURL": "",
                        "headersSize": -1,
                        "bodySize": 0,
                    }
                ),
                "cache": {},
                "timings": {"send": 0, "wait": 0, "receive": 0},
            }
            entries.append(entry)

        har = {
            "log": {
                "version": "1.2",
                "creator": {"name": "IntelOwl-Playwright", "version": "1.0"},
                "entries": entries,
            }
        }
        return json.dumps(har, default=str)

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
