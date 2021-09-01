"""
Sample using atheris to find bugs in a FastAPI application
"""
import atheris
from fastapi.testclient import TestClient


with atheris.instrument_imports():
    import sys
    from main import app

client = TestClient(app)


@atheris.instrument_func
def str_test(data):
    s = atheris.FuzzedDataProvider(data)
    random_str = s.ConsumeUnicodeNoSurrogates(sys.maxsize)
    random_str = random_str.replace("/", "")
    url = f"/not-kirby/{random_str}"
    response = client.get(url=url)

    assert response.status_code in [200], f"URL: {url}"


if __name__ == "__main__":
    atheris.Setup(sys.argv, str_test)
    atheris.Fuzz()
