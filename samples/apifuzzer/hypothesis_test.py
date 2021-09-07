from fastapi.testclient import TestClient
from hypothesis import assume, given, strategies as st


from main import app, Item


client = TestClient(app)


@given(st.builds(Item))
def test_model_good(obj):
    assert type(obj) == Item
    assert obj.name is not None


# @given(st.builds(Item))
# def test_post_item(item):
#     res = client.post("/items/", json=item.dict())
#     assert res.status_code == 200
#     assert res.json() == item.dict()


@given(st.builds(Item, price=st.floats(allow_infinity=False, allow_nan=False)))
def test_post_item_fixed(item):
    res = client.post("/items/", json=item.dict())
    assert res.status_code == 200
    assert res.json() == item.dict()


@given(st.text())
def test_not_kirby(s):
    assume("/" not in s)  # comment this to trigger 404s
    res = client.get(f"/not-kirby/{s}")
    assert res.status_code == 200
