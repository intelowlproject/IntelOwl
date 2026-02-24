import base64
from logging import getLogger

logger = getLogger(__name__)


def _encode_body(body: bytes | None) -> str:
    return base64.b64encode(body or b"").decode("utf-8")


def _headers_to_pairs(headers: dict) -> list:
    return list(headers.items())


def dump_playwright_request(entry: dict) -> dict:
    url = entry.get("url", "")
    logger.debug(f"Serialising Playwright request for url {url}")

    raw_response: dict | None = entry.get("response")
    serialised_response = None
    if raw_response:
        serialised_response = {
            "status_code": raw_response.get("status_code", 0),
            "reason": raw_response.get("reason", ""),
            "headers": _headers_to_pairs(raw_response.get("headers", {})),
            "body": _encode_body(raw_response.get("body")),
            "date": raw_response.get("date", ""),
            "cert": raw_response.get("cert", {}),
        }

    serialised_ws_messages = [
        {
            "from_client": msg.get("from_client", False),
            "content": _encode_body(msg.get("content")),
            "date": msg.get("date", ""),
        }
        for msg in entry.get("ws_messages", [])
    ]

    serialised: dict = {
        "id": str(entry.get("id", "")),
        "method": entry.get("method", ""),
        "url": url,
        "headers": _headers_to_pairs(entry.get("headers", {})),
        "body": _encode_body(entry.get("body")),
        "date": entry.get("date", ""),
        "resource_type": entry.get("resource_type", ""),
        "redirected_from": entry.get("redirected_from"),
        "redirected_to": entry.get("redirected_to"),
        "ws_messages": serialised_ws_messages,
        "cert": entry.get("cert", {}),
        "response": serialised_response,
    }

    logger.debug(f"Finished serialising Playwright request for url {url}")
    return serialised


def load_playwright_request(to_load: dict) -> dict:
    logger.debug(f"Deserialising Playwright request for url {to_load.get('url', '')}")

    decoded_response = None
    if to_load.get("response"):
        r = to_load["response"]
        decoded_response = {
            **r,
            "body": base64.b64decode(r["body"]),
        }

    decoded_ws_messages = [
        {**msg, "content": base64.b64decode(msg["content"])}
        for msg in to_load.get("ws_messages", [])
    ]

    decoded = {
        **to_load,
        "body": base64.b64decode(to_load["body"]),
        "ws_messages": decoded_ws_messages,
        "response": decoded_response,
    }

    logger.debug(f"Finished deserialising Playwright request for url {to_load.get('url', '')}")
    return decoded
