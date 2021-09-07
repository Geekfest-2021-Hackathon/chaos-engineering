"""Sample using locust to load test the main API. See https://docs.locust.io/en/stable/ """
from locust import HttpUser, task, between


class QuickstartUser(HttpUser):
    # delays between tasks
    wait_time = between(1, 2)

    # def on_start(self):
    #     self.client.post("/login", json={"username":"foo", "password":"bar"})

    @task
    def hello_chaos(self):
        self.client.get("/")

    @task(
        3
    )  # the 3 is the weight of the task (3 times more likely than tasks of weight 1)
    def view_item(self):
        item_id = 55
        self.client.get(f"/items/{item_id}")

    @task(3)
    def create_item(self):
        price = 12.34
        test_item = {
            "name": "test",
            "description": "blabla",
            "price": price,
            "tax": 2.5,
        }
        self.client.post("/items", json=test_item)
