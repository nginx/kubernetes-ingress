import os

import yaml
from locust import HttpUser, task

host = ""


class TestAPResponse(HttpUser):
    # locust class to be invoked
    def on_start(self):
        # get host from appprotect-ingress yaml before each test
        ap_yaml = os.path.join(os.path.dirname(__file__), "../data/appprotect-ingress.yaml")
        with open(ap_yaml) as f:
            docs = yaml.safe_load_all(f)
            for dep in docs:
                self.host = dep["spec"]["rules"][0]["host"]
        print("Setup finished")

    @task
    def send_block_request(self):
        # Send invalid request while dataguard alarm policy is active
        response = self.client.get(url="/<script>", headers={"host": self.host}, verify=False)
        print(response.text)

    @task
    def send_allow_request(self):
        # Send valid request while dataguard alarm policy is active
        response = self.client.get(url="", headers={"host": self.host}, verify=False)
        print(response.text)

    min_wait = 400
    max_wait = 1400
