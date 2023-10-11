import base64
import hashlib
import hmac

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import Message


class HMACMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, shared_secret: str):
        super().__init__(app)
        self.shared_secret = shared_secret

    def compute_hmac(self, payload: bytes):
        """
        Documentation can be found here:
        https://github.com/MicrosoftDocs/msteams-docs/blob/main/msteams-platform/webhooks-and-connectors/how-to/add-outgoing-webhook.md
        """
        digest = hmac.new(
            base64.b64decode(self.shared_secret),
            payload,
            hashlib.sha256,
        ).digest()
        signature_header = "HMAC " + base64.b64encode(digest).decode()
        return signature_header

    async def set_body(self, request: Request):
        receive_ = await request._receive()

        async def receive() -> Message:
            return receive_

        request._receive = receive
        
    async def dispatch(self, request, call_next):
        await self.set_body(request)
        body = await request.body()
        authorization = request.headers.get("authorization")
        if not authorization:
            return Response(
                status_code=400,
                content="Missing authorization header",
            )
        hmac_hash = self.compute_hmac(body)
        if not hmac_hash == authorization:
            return Response(
                status_code=401,
                content="Unauthorized or wrong key",
            )

        response = await call_next(request)
        return response
