import os
import tempfile
import time
import uuid

import pytest

# isolated database + test-only secrets, set before the app is imported
_tmp = tempfile.mkdtemp()
os.environ["DB_PATH"] = os.path.join(_tmp, "test_wallet.db")
os.environ.setdefault("JWT_SECRET", uuid.uuid4().hex + uuid.uuid4().hex)
os.environ.setdefault("HMAC_SECRET", uuid.uuid4().hex + uuid.uuid4().hex)
os.environ["ADMIN_USERNAME"] = "admin_test"
os.environ["ADMIN_PASSWORD"] = "Admin-Test-Pass-1"   # test fixture only, not a real credential

from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402
from tests.helpers import Api  # noqa: E402


@pytest.fixture(scope="session")
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture
def api(client):
    return Api(client)


def unique(prefix="u"):
    return f"{prefix}_{uuid.uuid4().hex[:10]}"


@pytest.fixture
def now():
    return int(time.time())
