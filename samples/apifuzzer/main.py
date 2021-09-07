"""
Sample API (fastapi based)  used to test API fuzzers. API normally starts with the container,
 but can also be used by test clients.
"""

from typing import Optional

from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()


class Item(BaseModel):
    name: str
    description: Optional[str] = None
    price: float
    tax: Optional[float] = None


def not_kirby(s: str):
    """Returns True as long as the given text is not 'kirby'"""

    # print(s)

    if len(s) < 5:
        return True

    if s[0] == "k":
        if s[1] == "i":
            if s[2] == "R":
                if s[3] == "b":
                    if s[4] == "Y":
                        raise ValueError(f"{s} is not accepted by this function.")

    return True


@app.get("/")
def read_root():
    return {"Hello": "Chaos"}


@app.get("/items/{item_id}")
def read_item(item_id: int, q: Optional[str] = None):
    if item_id > 100:
        raise RuntimeError(f"This id ({item_id}) is not allowed - too big")

    if q and len(q) > 5:
        if q[0] == "k":
            if q[1] == "i":
                if q[2] == "r":
                    if q[3] == "b":
                        if q[4] == "y":
                            raise ValueError("kirby is not accepted by this function.")

    return {"item_id": item_id, "q": q}


@app.get("/not-kirby/")
def blank_kirb():
    return "No string provided."


@app.get("/not-kirby/{s}")
def kirb(s: str):
    not_kirby(s)


@app.post("/items/")
@app.post("/items", include_in_schema=False)
async def create_item(item: Item):
    # print(f"Creating item: {item.dict()}...")
    return item
