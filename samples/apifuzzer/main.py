from typing import Optional

from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()


class Model(BaseModel):
    name: str
    count: int


class Item(BaseModel):
    name: str
    description: Optional[str] = None
    price: float
    tax: Optional[float] = None


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


@app.post("/items/")
@app.post("/items", include_in_schema=False)
async def create_item(item: Item):


    print(item.dict())
    return item
#
# @app.post("/models/")
# async def create_model(model: Model):
#     print(model.dict())
#     return model
