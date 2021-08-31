from fastapi.testclient import TestClient
from main import app

API_URL = "http://127.0.0.1:555"
client = TestClient(app)


def test_good():
    response = client.get(url=f"{API_URL}/not-kirby/good")

    assert response.status_code in [200]
