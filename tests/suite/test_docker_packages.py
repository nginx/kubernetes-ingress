import json
import re

import docker

client = docker.from_env()
images = json.loads(open("tests/data/modules/data.json").read())

for image in images["images"]:
    regexInstalled = image["regex"]
    for package in image["packages"]:
        command = f"{image['cmd']} {package}"
        output = client.containers.run(
            image["image"], command, entrypoint="", platform=image["platform"], auto_remove=True, detach=False
        )
        result = re.search(regexInstalled, output.decode("utf-8").strip())
        assert result, f"{package} not found in {image['image']}, output: {output.decode('utf-8').strip()}"
        print(image["image"], result.group(1, 2, 3))
