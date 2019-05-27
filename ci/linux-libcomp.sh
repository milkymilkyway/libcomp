#!/bin/bash
set -ex

# Load the global settings.
source "ci/global.sh"

#
# Dependencies
#

cd "${ROOT_DIR}"
mkdir build
cd build

echo "Installing external dependencies"
tar xf "${CACHE_DIR}/external-${EXTERNAL_VERSION}-${PLATFORM}.tar.bz2" | "${ROOT_DIR}/ci/report-progress.sh"
mv external* ../binaries
chmod +x ../binaries/ttvfs/bin/ttvfs_gen
echo "Installed external dependencies"

#
# Build
#

cd "${ROOT_DIR}/build"

echo "Running cmake"
cmake -DCMAKE_INSTALL_PREFIX="${ROOT_DIR}/build/install" \
    -DCOVERALLS="$COVERALLS_ENABLE" -DBUILD_OPTIMIZED="$BUILD_OPTIMIZED" \
    -DSINGLE_SOURCE_PACKETS=ON \ -DSINGLE_OBJGEN="${SINGLE_OBJGEN}" \
    -DUSE_COTIRE=ON -DGENERATE_DOCUMENTATION=ON -G "${GENERATOR}" ..

echo "Running build"
cmake --build . --target package

echo "Copying package to cache for next stage"

mv libcomp-*.tar.bz2 "libcomp-${PLATFORM}.tar.bz2"

set +x

if [ "$CMAKE_GENERATOR" != "Ninja" ]; then
    if [[ ! -z "$DROPBOX_OAUTH_BEARER" ]]; then
        dropbox_setup
        dropbox_upload libcomp "libcomp-${PLATFORM}.tar.bz2"
    fi
fi
