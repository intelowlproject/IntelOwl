class WSAuthMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        user = scope["user"]
        if user.is_anonymous:
            return await send({"type": "websocket.close", "code": 1008})

        return await self.app(scope, receive, send)
