import base64
import hashlib
import hmac

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response


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

    async def dispatch(self, request, call_next):
        authorization = request.headers.get("authorization")
        if not authorization:
            return Response(
                status_code=400,
                content="Missing authorization header",
            )
        body = await request.body()
        hmac_hash = self.compute_hmac(body)
        if not hmac_hash == authorization:
            return Response(
                status_code=401,
                content="Unauthorized or wrong key",
            )

        response = await call_next(request)
        return response
