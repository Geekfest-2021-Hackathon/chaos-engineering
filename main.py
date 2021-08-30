from fastapi import FastAPI
from pydantic import BaseModel


app = FastAPI()


class Model(BaseModel):
    name: str
    count: int


@app.get("/")
def root():
    """
    Returns a simple string when the user makes a request to the root address. Can serve as a health check to make sure
    the application is running.

    :return: None
    """
    output = (
        "Notifications Bot is running. You can find more information in the git repo here: "
        "https://gitlab.int.bell.ca/vna3/notifications-bot"
    )
    return output


@app.post("/test/")
def send_message(payload: Model):
    """
    """

    print(payload.dict())

    return {"message": "OK"}
