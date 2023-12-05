import hashlib

import pytest
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from starlette_hmac.middleware import HMACMiddleware


@pytest.fixture
def shared_secret():
    return "RZ9FvpusdSdjHT0hjv3eRgw4WNj12GYZu3pN3r/jVKE="


@pytest.fixture
def middleware_kwargs() -> dict:
    return {
        "header_field": "authorization",
        "digestmod": hashlib.sha256,
        "header_format": "HMAC {}",
    }


@pytest.fixture
def app(shared_secret, middleware_kwargs) -> Starlette:
    async def get(request: Request):
        return JSONResponse({"hello": "world"})

    async def post(request: Request):
        json = await request.json()
        return JSONResponse(json)

    app = Starlette(
        debug=True,
        routes=[
            Route("/get", get, methods=["GET"]),
            Route("/post", post, methods=["POST"]),
        ],
        middleware=[
            Middleware(HMACMiddleware, shared_secret=shared_secret, **middleware_kwargs)
        ],
    )

    return app


@pytest.fixture
def client(app):
    return TestClient(app)


def test_simple_hmac(app):
    shared_secret = "RZ9FvpusdSdjHT0hjv3eRgw4WNj12GYZu3pN3r/jVKE="
    payload = b'{"text": "test"}'
    middleware = HMACMiddleware(app=app, shared_secret=shared_secret)
    hmac = middleware.compute_hmac(payload)
    assert hmac == "uYRUNd8Qu0vogK9Kv92FWZrFMsoroEl0RfE8hMUJAl8="


def test_unauthorized(app):
    client = TestClient(app)
    response = client.post("/api/webhook")
    assert response.status_code == 400


def test_authentication(app):
    client = TestClient(app)
    response = client.post("/api/webhook", headers=[("authorization", "HMAC 1234")])
    assert response.status_code == 401


def test_authentication_pass(client):
    payload = {"text": "test"}
    response = client.post(
        "/post",
        json=payload,
        headers=[
            ("authorization", "HMAC uYRUNd8Qu0vogK9Kv92FWZrFMsoroEl0RfE8hMUJAl8=")
        ],
    )
    assert response.status_code == 200
    assert "text" in response.json()


@pytest.mark.parametrize(
    "middleware_kwargs",
    [
        {
            "header_field": "x-hub-signature",
            "digestmod": hashlib.sha256,
            "header_format": "sha256={}",
        }
    ],
)
def test_header_field(middleware_kwargs, client):
    payload = {"text": "test"}
    response = client.post(
        "/post",
        json=payload,
        headers=[
            ("x-hub-signature", "sha256=uYRUNd8Qu0vogK9Kv92FWZrFMsoroEl0RfE8hMUJAl8=")
        ],
    )
    assert response.status_code == 200
    assert "text" in response.json()
