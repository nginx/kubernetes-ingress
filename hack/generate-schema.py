#!/usr/bin/env python3

from copy import deepcopy
from dataclasses import dataclass, field
from json import dump as json_dump
from json import load as json_load
from json import loads as json_loads
from pathlib import Path
from re import sub as re_sub
from sys import exit
from typing import Any
from urllib.parse import urlparse, urlunparse
from urllib.request import urlopen


@dataclass
class SchemaGenerator:
    """Generate a schema by embedding referenced definitions"""

    root: dict
    _referenced_schemas: dict[str, object] = field(default_factory=dict, init=False)

    def update_references(self) -> None:
        """Embedd output file from input file by embedding referenced definitions"""
        if "$defs" not in self.root:
            self.root["$defs"] = {}
        self._update_references(self.root)

    def _update_references(self, schema: Any, base_url: str | None = None) -> None:
        """Update $ref references to point to local $defs"""

        if isinstance(schema, dict):
            # Create a new dict to avoid modifying during iteration
            for key, value in schema.items():
                if key == "$ref":
                    if value.startswith("https://"):
                        # Convert external reference to local reference
                        parsed_result = urlparse(value)
                        base_url = urlunparse(
                            (parsed_result.scheme, parsed_result.netloc, parsed_result.path, "", "", "")
                        )
                        schema[key] = self._import_definition(base_url, parsed_result.fragment.removeprefix("/"))
                    elif base_url:
                        schema[key] = self._import_definition(base_url, value.removeprefix("#/"))
                else:
                    self._update_references(value, base_url)
        elif isinstance(schema, list):
            for item in schema:
                self._update_references(item)

    def _import_definition(self, base_url: str, path: str) -> str:
        """Copy the definitions tha are referenced in the schema and returns the local reference"""
        base_url_slug = self._slug_url(base_url)

        if base_url_slug not in self._referenced_schemas:
            self._referenced_schemas[base_url_slug] = self._download_schema(base_url)
        source_level = self._referenced_schemas[base_url_slug]

        if base_url_slug not in self.root["$defs"]:
            self.root["$defs"][base_url_slug] = {}
        target_level = self.root["$defs"][base_url_slug]

        parts = path.split("/")
        for i, part in enumerate(parts):
            if part not in target_level:
                target_level[part] = {}

            if i == len(parts) - 1:
                target_level[part] = deepcopy(source_level[part])
                self._update_references(target_level[part], base_url)
            else:
                source_level = source_level[part]
                target_level = target_level[part]
        return f"#/$defs/{base_url_slug}/{path}"

    """Download schema"""

    def _download_schema(self, url: str) -> Any:
        """Download Kubernetes JSON schema definitions from GitHub"""
        try:
            print(f"Downloading Kubernetes definitions from {url}...")
            with urlopen(url) as response:
                data = response.read()
                return json_loads(data)
        except Exception as e:
            print(f"Error downloading Kubernetes definitions: {e}")
            exit(1)

    def _slug_url(self, url: str) -> str:
        return re_sub("[^a-zA-Z0-9]", "", url)


def main():
    chart_dir = Path(__file__).parent.parent / "charts" / "nginx-ingress"
    input_file = chart_dir / "values.schema.json.in"
    output_file = chart_dir / "values.schema.json"

    # Read the input schema
    with open(input_file) as f:
        schema = json_load(f)

    # Generate output schema
    SchemaGenerator(schema).update_references()

    # Write the output schema
    with open(output_file, "w") as f:
        json_dump(schema, f, indent=2)


if __name__ == "__main__":
    main()
