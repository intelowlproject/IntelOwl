import base64
from datetime import datetime

from seleniumwire.request import Request, Response, WebSocketMessage


def dump_seleniumwire_requests(request: Request) -> dict:
    """
    Serializer for seleniumwire.request.Request
    """
    response: Response = request.response
    return {
        "id": request.id if request.id else "",
        "method": request.method,
        "url": request.url,
        "headers": request.headers.items(),
        "body": base64.b64encode(request.body).decode("utf-8"),
        "date": request.date.strftime("%Y-%m-%d, %H:%M:%S.%f"),
        "ws_message": (
            [
                {
                    "from_client": message.from_client,
                    "content": base64.b64encode(message.content).decode("utf-8"),
                    "date": message.date.strftime("%Y-%m-%d, %H:%M:%S.%f"),
                }
                for message in request.ws_messages
            ]
            if request.ws_messages
            else []
        ),
        "cert": request.cert,
        "response": (
            {
                "status_code": response.status_code,
                "reason": response.reason,
                "headers": response.headers.items(),
                "body": base64.b64encode(response.body).decode("utf-8"),
                "date": response.date.strftime("%Y-%m-%d, %H:%M:%S.%f"),
                # cert is not always available in response
                "cert": response.cert if hasattr(response, "cert") else {},
            }
            if response
            else None
        ),
    }


def load_seleniumwire_requests(to_load: dict) -> Request:
    response_to_load = to_load["response"]
    response = (
        Response(
            status_code=response_to_load["status_code"],
            reason=response_to_load["reason"],
            headers=response_to_load["headers"],
            # body gets re-encoded into utf-8 by its setter method
            body=base64.b64decode(response_to_load["body"]),
        )
        if response_to_load
        else None
    )

    request = Request(
        method=to_load["method"],
        url=to_load["url"],
        headers=to_load["headers"],
        body=base64.b64decode(to_load["body"]),
    )
    request.id = to_load["id"]
    request.date = datetime.strptime(to_load["date"], "%Y-%m-%d, %H:%M:%S.%f")
    request.ws_messages = (
        [
            WebSocketMessage(
                from_client=message["from_client"],
                content=base64.b64decode(message["content"]),
                date=datetime.strptime(message["date"], "%Y-%m-%d, %H:%M:%S.%f"),
            )
            for message in to_load["ws_messages"]
        ]
        if "ws_messages" in to_load.keys()
        else []
    )
    request.cert = to_load["cert"]

    if response:
        response.date = datetime.strptime(
            response_to_load["date"], "%Y-%m-%d, %H:%M:%S.%f"
        )
        if response_to_load["cert"]:
            response.cert = response_to_load["cert"]
        request.response = response

    return request
