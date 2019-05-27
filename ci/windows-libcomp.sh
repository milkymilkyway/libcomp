#!/bin/bash
set -ex

# Load the global settings.
source "ci/global.sh"

# Run the cache again just in case it was not warmed.
source "ci/windows-warmcache.sh"

#
# Dependencies
#

cd "${ROOT_DIR}"
mkdir build
cd build

echo "Installing external dependencies"
unzip "${CACHE_DIR}/external-${EXTERNAL_VERSION}-${PLATFORM}.zip" | "${ROOT_DIR}/ci/report-progress.sh"
mv external* ../binaries
echo "Installed external dependencies"

echo "Installing Doxygen"
mkdir doxygen
cd doxygen
unzip "${CACHE_DIR}/doxygen.zip" | "${ROOT_DIR}/ci/report-progress.sh"
cd ..
export PATH="${ROOT_DIR}/build/doxygen;${PATH}"
echo "Installed Doxygen"

#
# Build
#

cd "${ROOT_DIR}/build"

echo "Running cmake"
cmake -DCMAKE_INSTALL_PREFIX="${ROOT_DIR}/build/install" \
    -DGENERATE_DOCUMENTATION=ON -DWINDOWS_SERVICE=ON \
    -DCMAKE_CUSTOM_CONFIGURATION_TYPES="$CONFIGURATION" -G"$GENERATOR" ..

echo "Running build"
cmake --build . --config "$CONFIGURATION" --target package

echo "Copying package to cache for next stage"

mv libcomp-*.zip "libcomp-${PLATFORM}.zip"

set +x

if [[ ! -z "$DROPBOX_OAUTH_BEARER" ]]; then
    dropbox_setup
    dropbox_upload libcomp "libcomp-${PLATFORM}.zip"
fi
