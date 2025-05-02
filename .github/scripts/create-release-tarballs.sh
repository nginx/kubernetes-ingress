#!/usr/bin/env bash

set -e

directory=$1
version=$2
tarball_dir=${TARBALL_DIR:-tarballs}
releases=$(find "${directory}" -mindepth 1 -type d)
syft_binary=${SYFT_BIN:-"syft"}
cosign_binary=${COSIGN_BIN:-"cosign"}

if [ ! -d "${tarball_dir}" ]; then
    mkdir "${tarball_dir}"
fi

for i in ${releases}; do
    # fix for v1 in kubernetes-ingress_linux_amd64_v1
    if [[ ${i} =~ v1 ]]; then
        mv "${i}" "${i%*_v1}"
        i=${i%*_v1}
    fi

    if [[ ${i} =~ aws ]]; then
        continue
    fi
    product_name=$(basename "${i}" | cut -d '_' -f 1)
    product_arch=$(echo "${i}" | cut -d '_' -f 2-)
    product_release="${product_name}_${version}_${product_arch}"
    # shellcheck disable=SC2086
    tarball_name="${tarball_dir}/${product_release}.tar.gz"
    cp -r "${i}" "${directory}/${product_release}"
    cp README.md LICENSE CHANGELOG.md "${directory}/${product_release}"

    tar -czf "${tarball_name}" "${directory}/${product_release}"
    ${syft_binary} scan file:"${directory}/${product_release}/nginx-ingress" -o spdx-json > "${tarball_name}.spdx.json"
    pushd "${tarball_dir}"
    sha256sum "${product_release}.tar.gz" >> "${product_name}_${version}_checksums.txt"
    sha256sum "${product_release}.tar.gz.spdx.json" >> "${product_name}_${version}_checksums.txt"
    popd
done

checksum_file=$(ls "${tarball_dir}"/*_checksums.txt )
${cosign_binary} sign-blob "${checksum_file}" --output-signature="${checksum_file}.sig" --output-certificate="${checksum_file}.pem" -y
