#!/usr/bin/env python

import json
import re

import docker

client = docker.from_env()
images = json.loads(open("tests/data/modules/data.json").read())

for image in images["images"]:
    regexInstalled = image["regex"]
    for package in image["packages"]:
        command = f"{image['cmd']} {package['name']}"
        output = client.containers.run(
            image["image"], command, entrypoint="", platform=image["platform"], auto_remove=True, detach=False
        )
        result = re.search(regexInstalled, output.decode("utf-8").strip())
        assert result, f"{package['name']} not found in {image['image']}, output: {output.decode('utf-8').strip()}"
        assert result.group(2).startswith(
            package["version"]
        ), f"{package['name']} version {package['version']} does not match {result.group(2)}"
        print(image["image"], result.group(1, 2, 3))
