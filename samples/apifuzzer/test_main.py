# What normal testing of a fastapi app looks like. See https://fastapi.tiangolo.com/tutorial/testing/
# CAn be run with 'pytest test_main.py'

from fastapi.testclient import TestClient
from main import app

API_URL = "http://127.0.0.1:555"
client = TestClient(app)


def test_not_kirby_good():
    response = client.get(url=f"{API_URL}/not-kirby/good")

    assert response.status_code in [200]
