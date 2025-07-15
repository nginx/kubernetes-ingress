#!/usr/bin/env python

import argparse
import json
import os
import re

import docker
import docker.errors

# parse args
parser = argparse.ArgumentParser()
parser.add_argument("-t", "--tag", type=str, help="NGINX Ingress Controller image tag", default="edge")
args = parser.parse_args()

client = docker.from_env()
script_dir = os.path.dirname(os.path.abspath(__file__))
with open(f"{script_dir}/../data/modules/data.json") as file:
    images = json.load(file)

    for image in images["images"]:
        regexInstalled = image["regex"]
        tag = f"{args.tag}{image['tag_suffix']}"
        try:
            client.images.get(f"{image['image']}:{tag}")
            print(f"Image {image['image']}:{tag} already exists, skipping pull")
        except docker.errors.ImageNotFound:
            print(f"Image {image['image']}:{tag} not found, pulling...")
            ## pull the image
            print(f"Pulling image {image['image']}:{tag} for platform {image['platform']}")
            i = client.images.pull(repository=image["image"], tag=tag, platform=image["platform"])
            print(f"Image {i.id} pulled successfully")
        for package in image["packages"]:
            command = f"{image['cmd']} {package['name']}"
            output = ""
            try:
                output = client.containers.run(
                    f"{image['image']}:{tag}",
                    command,
                    entrypoint="",
                    platform=image["platform"],
                    auto_remove=True,
                    detach=False,
                )
            except (docker.errors.ContainerError, docker.errors.NotFound) as e:
                print(f"Container error: {e}, retrying")
                output = client.containers.run(
                    f"{image['image']}:{tag}",
                    command,
                    entrypoint="",
                    platform=image["platform"],
                    auto_remove=True,
                    detach=False,
                )
            result = re.search(regexInstalled, output.decode("utf-8").strip())
            assert result, f"{package['name']} not found in {image['image']}, output: {output.decode('utf-8').strip()}"
            assert result.group(2).startswith(
                package["version"]
            ), f"{package['name']} version {package['version']} does not match {result.group(2)}"
            print(image["image"], result.group(1, 2, 3))
