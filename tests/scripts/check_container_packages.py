#!/usr/bin/env python

import argparse
import json
import logging
import os
import re

import docker
import docker.errors

# parse args
parser = argparse.ArgumentParser()
parser.add_argument("-t", "--tag", type=str, help="NGINX Ingress Controller image tag", default="edge")
parser.add_argument("-l", "--log", type=str, help="log file", required=False)
args = parser.parse_args()

# Create a logger
logger = logging.getLogger("package_checker")
logger.setLevel(logging.DEBUG)

# Create a stream handler (for stdout)
stream_handler = logging.StreamHandler()
stream_handler.setLevel(logging.DEBUG)
stream_handler.setFormatter(logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s"))
logger.addHandler(stream_handler)

if args.log:
    # Create a file handler
    file_handler = logging.FileHandler(args.log)
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(file_handler)

systems = {
    "alpine": {
        "cmd": "apk list",
        "regex": "^(.+?)-(\\d+.+?)\\s+(\\w+).*\\[installed\\]",
    },
    "debian": {
        "cmd": "dpkg -l",
        "regex": "ii\\s+(.+?)\\s+(.+?)\\s+(\\w+?)\\s",
    },
    "ubi": {
        "cmd": "rpm -q",
        "regex": "(.+?)-(\\d+.+)(?:\\.ngx)?\\.(\\w+)",
    },
}

client = docker.from_env()
script_dir = os.path.dirname(os.path.abspath(__file__))
with open(f"{script_dir}/../data/modules/data.json") as file:
    images = json.load(file)

    for image in images["images"]:
        for platform in image["platforms"]:
            image_name = image["image"]
            regex = systems[image["system"]]["regex"]
            cmd = systems[image["system"]]["cmd"]
            tag = f"{args.tag}{image['tag_suffix']}"
            try:
                i = client.images.get(f"{image['image']}:{tag}")
                ## check if the image is for the correct platform
                if platform != i.attrs["Os"]:
                    raise docker.errors.ImageNotFound(
                        f"Image {image['image']}:{tag} is not for platform {platform}, found {i.attrs['Os']}"
                    )
            except docker.errors.ImageNotFound:
                ## pull the image
                logger.debug(f"Pulling image {image['image']}:{tag} for platform {platform}")
                i = client.images.pull(repository=image_name, tag=tag, platform=platform)
                logger.debug(f"Image {i.id} pulled successfully")
            for package in image["packages"]:
                command = f"{cmd} {package['name']}"
                output = ""
                try:
                    output = client.containers.run(
                        f"{image['image']}:{tag}",
                        command,
                        entrypoint="",
                        platform=platform,
                        auto_remove=True,
                        detach=False,
                    )
                except (docker.errors.ContainerError, docker.errors.NotFound) as e:
                    logger.debug(f"{e}, retrying")
                    output = client.containers.run(
                        f"{image['image']}:{tag}",
                        command,
                        entrypoint="",
                        platform=platform,
                        auto_remove=True,
                        detach=False,
                    )
                result = re.search(regex, output.decode("utf-8").strip())
                assert result, logger.error(
                    f"{package['name']} not found in {image['image']}, output: {output.decode('utf-8').strip()}"
                )
                assert result.group(2).startswith(package["version"]), logger.error(
                    f"{package['name']} version {package['version']} does not match {result.group(2)}"
                )
                logger.info(f"{image_name}:{tag}, {result.group(1)}, {result.group(2)}, {result.group(3)}")
