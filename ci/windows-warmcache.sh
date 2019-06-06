#!/bin/bash
set -ex

# Load the global settings.
source "ci/global.sh"

cd "${CACHE_DIR}"

# Doxygen for Windows (only warm from one job)
if [ "$PLATFORM" != "win32" ]; then
    echo "Downloading Doxygen"
    if [ ! -f doxygen.zip ]; then
        curl -Lo doxygen.zip "https://github.com/comphack/external/releases/download/${DOXYGEN_EXTERNAL_RELEASE}/doxygen-${DOXYGEN_VERSION}.windows.x64.bin.zip"
    fi
fi

# OpenSSL for Windows (only needed for the full build)
if [ "$PLATFORM" != "win32" ]; then
    echo "Downloading OpenSSL"
    if [ ! -f "OpenSSL-${OPENSSL_VERSION}-${PLATFORM}.msi" ]; then
        curl -Lo "OpenSSL-${OPENSSL_VERSION}-${PLATFORM}.msi" "https://github.com/comphack/external/releases/download/${DOXYGEN_EXTERNAL_RELEASE}/Win64OpenSSL-${OPENSSL_VERSION}.msi"
    fi
fi

# External dependencies for Windows
echo "Downloading the external dependencies"
if [ ! -f "external-0.1.1-${PLATFORM}.zip" ]; then
    curl -Lo "external-0.1.1-${PLATFORM}.zip" "https://github.com/comphack/external/releases/download/${EXTERNAL_RELEASE}/external-${EXTERNAL_VERSION}-${PLATFORM}.zip"
fi

# Just for debug to make sure the cache is setup right
echo "State of cache:"
ls -lh
