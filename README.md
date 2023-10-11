# starlette-hmac

HMAC Middleware for the pythonic Starlette API framework

### Installation

```shell
$ pip install starlette-hmac
```

### Usage

```python
import os
from starlette.applications import Starlette
from starlette_hmac.middleware import HMACMiddleware

shared_secret = os.environ.get("SHARED_SECRET")

app = Starlette()
app.add_middleware(HMACMiddleware, shared_secret=shared_secret)
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

