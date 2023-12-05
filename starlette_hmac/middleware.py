import base64
import hashlib
import hmac

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import Message


class HMACMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app,
        shared_secret: str,
        header_field: str = "authorization",
        digestmod: str = hashlib.sha256,
        header_format: str = "HMAC {}",
    ):
        super().__init__(app)
        self.shared_secret = shared_secret
        self.header_field = header_field
        self.digestmod = digestmod
        self.header_format = header_format

    def compute_hmac(self, payload: bytes):
        """
        Documentation can be found here:
        https://github.com/MicrosoftDocs/msteams-docs/blob/main/msteams-platform/webhooks-and-connectors/how-to/add-outgoing-webhook.md
        """
        digest = hmac.new(
            base64.b64decode(self.shared_secret),
            payload,
            self.digestmod,
        ).digest()
        return base64.b64encode(digest).decode()

    async def set_body(self, request: Request):
        receive_ = await request._receive()

        async def receive() -> Message:
            return receive_

        request._receive = receive

    async def dispatch(self, request, call_next):
        await self.set_body(request)
        body = await request.body()
        hmac_header = request.headers.get(self.header_field)
        if not hmac_header:
            return Response(
                status_code=400,
                content="Missing authorization header",
            )
        hmac_hash = self.compute_hmac(body)
        if not self.header_format.format(hmac_hash) == hmac_header:
            return Response(
                status_code=401,
                content="Unauthorized or wrong key",
            )

        response = await call_next(request)
        return response
