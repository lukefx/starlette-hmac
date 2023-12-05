# starlette-hmac

HMAC Middleware for the pythonic Starlette API framework

### Installation

```shell
$ pip install starlette-hmac
```

### Usage

This will verify that the request will be done with an `authorization` header with value `HMAC <hmac hash of body>`

```python
import os
from starlette.applications import Starlette
from starlette_hmac.middleware import HMACMiddleware

shared_secret = os.environ.get("SHARED_SECRET")

app = Starlette()
app.add_middleware(HMACMiddleware, shared_secret=shared_secret)
```

### Advanced usage

To customize header name or value of you can pass the needed parameters to the middleware.
This example verifies that the request was done with an `x-hub-signature` header with value `sha256=<hash>`

```python
import os
import hashlib
from starlette.applications import Starlette
from starlette_hmac.middleware import HMACMiddleware

shared_secret = os.environ.get("SHARED_SECRET")

app = Starlette()
app.add_middleware(HMACMiddleware, 
                   shared_secret=shared_secret, 
                   header_field="x-hub-signature", 
                   digestmod=hashlib.sha256, 
                   header_format="sha256={}"
)
```

### Develop

This project uses poetry to manage its development environment, and pytest as its test runner. To install development dependencies:

```shell
$ poetry install
```

To run the tests:

```shell
$ poetry shell
$ pytest
```

