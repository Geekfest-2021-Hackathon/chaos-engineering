"""
Sample using atheris to find bugs in a FastAPI application
"""
import atheris
from fastapi.testclient import TestClient
from main import app


with atheris.instrument_imports():
    import sys

API_URL = "http://127.0.0.1:9060"
client = TestClient(app)


@atheris.instrument_func
def str_test(data):
    s = atheris.FuzzedDataProvider(data)
    random_str = s.ConsumeUnicodeNoSurrogates(sys.maxsize)
    response = client.get(url=f"{API_URL}/not-kirby/{random_str}")

    assert response.status_code in [200]


if __name__ == "__main__":
    atheris.Setup(sys.argv, str_test)
    atheris.Fuzz()
