from starlette.responses import JSONResponse


class RequestBodyLimit:
    def __init__(self, app, max_bytes: int):
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope["method"] != "POST":
            await self.app(scope, receive, send)
            return

        body = bytearray()
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            chunk = message.get("body", b"")
            if len(body) + len(chunk) > self.max_bytes:
                await JSONResponse({"detail": "Request body is too large."}, status_code=413)(scope, receive, send)
                return
            body.extend(chunk)
            if not message.get("more_body", False):
                break

        buffered = bytes(body)
        del body

        async def replay_body():
            nonlocal buffered
            if buffered is None:
                return await receive()
            message = {"type": "http.request", "body": buffered, "more_body": False}
            buffered = None
            return message

        await self.app(scope, replay_body, send)
