#!/bin/bash

# Script to automatically update OpenShift version annotations based on Red Hat API
# This script finds the minimum OpenShift version with Extended Update Support Add-On available
# and updates both bundle.Dockerfile and bundle/metadata/annotations.yaml

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Red Hat API endpoint for OpenShift lifecycle
API_URL="https://access.redhat.com/product-life-cycles/api/v1/products?name=Openshift%20Container%20Platform%204"

echo "Fetching OpenShift lifecycle data from Red Hat API..."

# Fetch the API data and extract supported versions
api_data=$(curl -sSf "$API_URL")
curl_exit=$?

if [ $curl_exit -ne 0 ]; then
    echo "Error: Failed to fetch data from Red Hat API (exit code: $curl_exit)"
    exit 1
fi

# Validate API response structure
if ! echo "$api_data" | jq -e '.data' > /dev/null 2>&1; then
    echo "Error: Invalid API response - missing 'data' field"
    exit 1
fi

if [ "$(echo "$api_data" | jq '.data | length')" -eq 0 ]; then
    echo "Error: API response contains empty data array"
    exit 1
fi

# Extract versions that have Extended Update Support Add-On available
# (versions with "Extended update support" phase that is not "N/A")
supported_versions=$(echo "$api_data" | jq -r '
    .data[0].versions[] |
    select(.phases[] | select(.name == "Extended update support" and .date != "N/A")) |
    .name
' | sort -V)


if [ -z "$supported_versions" ]; then
    echo "Error: No supported versions found"
    exit 1
fi

# Get the minimum supported version
min_version=$(echo "$supported_versions" | head -n 1)

echo "Currently supported OpenShift versions:"
echo "$supported_versions" | sed 's/^/  - /'
echo ""
echo "Minimum supported version: $min_version"

# Update bundle.Dockerfile
dockerfile_path="$PROJECT_ROOT/bundle.Dockerfile"
if [ -f "$dockerfile_path" ]; then
    echo "Updating $dockerfile_path..."

    # Use sed to replace the OpenShift version label
    if grep -q "com.redhat.openshift.versions=" "$dockerfile_path"; then
        temp_file=$(mktemp)
        sed "s/LABEL com.redhat.openshift.versions=\"v[0-9]\+\.[0-9]\+\"/LABEL com.redhat.openshift.versions=\"v$min_version\"/" "$dockerfile_path" > "$temp_file"
        mv "$temp_file" "$dockerfile_path"
        echo "Updated bundle.Dockerfile"
    else
        echo "OpenShift version label not found in bundle.Dockerfile"
    fi
else
    echo "bundle.Dockerfile not found"
fi

# Update bundle/metadata/annotations.yaml
annotations_path="$PROJECT_ROOT/bundle/metadata/annotations.yaml"
if [ -f "$annotations_path" ]; then
    echo "Updating $annotations_path..."

    # Use sed to replace the OpenShift version annotation
    if grep -q "com.redhat.openshift.versions:" "$annotations_path"; then
        temp_file=$(mktemp)
        sed "s/com.redhat.openshift.versions: v[0-9]\+\.[0-9]\+/com.redhat.openshift.versions: v$min_version/" "$annotations_path" > "$temp_file"
        mv "$temp_file" "$annotations_path"
        echo "Updated annotations.yaml"
    else
        echo "OpenShift version annotation not found in annotations.yaml"
    fi
else
    echo "bundle/metadata/annotations.yaml not found"
fi

# Update Makefile OPENSHIFT_VERSION variable
makefile_path="$PROJECT_ROOT/Makefile"
if [ -f "$makefile_path" ]; then
    echo "Updating $makefile_path..."

    # Use sed to replace the OPENSHIFT_VERSION variable
    if grep -q "OPENSHIFT_VERSION ?=" "$makefile_path"; then
        temp_file=$(mktemp)
        sed "s/OPENSHIFT_VERSION ?= v[0-9]\+\.[0-9]\+/OPENSHIFT_VERSION ?= v$min_version/" "$makefile_path" > "$temp_file"
        mv "$temp_file" "$makefile_path"
        echo "Updated Makefile"
    else
        echo "OPENSHIFT_VERSION variable not found in Makefile"
    fi
else
    echo "Makefile not found"
fi

echo ""
echo "OpenShift version updated to v$min_version"
echo ""
echo "Note: This version (v$min_version) will automatically support all newer OpenShift versions according to Red Hat's operator bundle specification."
