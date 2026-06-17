#!/usr/bin/env bash
# setup-liboqs.sh — fetch and install liboqs for pq-sign.
#
# liboqs is rarely packaged by distributions, so this builds it from source.
# By default it installs SYSTEM-WIDE into /usr/local (so a plain `make` and
# `./pq-sign` just work). Pass a different prefix to install locally without
# root, e.g.:
#
#   ./setup-liboqs.sh                 # -> /usr/local   (uses sudo)
#   PREFIX="$PWD/.local" ./setup-liboqs.sh   # -> ./.local (no root)
#
# Only the signature schemes pq-sign uses are built.
set -euo pipefail

VERSION="${LIBOQS_VERSION:-0.12.0}"
PREFIX="${PREFIX:-/usr/local}"
BUILD_DIR="$(mktemp -d)"
trap 'rm -rf "$BUILD_DIR"' EXIT

for tool in git cmake ninja; do
    command -v "$tool" >/dev/null \
        || { echo "missing dependency: $tool (try: sudo apt install git cmake ninja-build)" >&2; exit 1; }
done

# Use sudo only when the install prefix is not writable by the current user.
SUDO=""
if [ ! -w "$PREFIX" ] && [ ! -w "$(dirname "$PREFIX")" ]; then
    SUDO="sudo"
fi

echo ">> Cloning liboqs $VERSION"
git clone --depth 1 --branch "$VERSION" \
    https://github.com/open-quantum-safe/liboqs.git "$BUILD_DIR/liboqs"

echo ">> Configuring (minimal: ML-DSA + SLH-DSA only) -> $PREFIX"
cmake -GNinja -S "$BUILD_DIR/liboqs" -B "$BUILD_DIR/build" \
    -DCMAKE_INSTALL_PREFIX="$PREFIX" \
    -DCMAKE_BUILD_TYPE=Release \
    -DOQS_BUILD_ONLY_LIB=ON \
    -DBUILD_SHARED_LIBS=ON \
    -DOQS_MINIMAL_BUILD="SIG_ml_dsa_44;SIG_ml_dsa_65;SIG_ml_dsa_87;SIG_sphincs_sha2_128f_simple;SIG_sphincs_sha2_192f_simple;SIG_sphincs_sha2_256f_simple"

echo ">> Building and installing into $PREFIX"
$SUDO ninja -C "$BUILD_DIR/build" install

# Some root umasks (027) create unreadable dirs; make sure non-root tools
# (pkg-config, the compiler) can read the headers and the .pc file.
$SUDO chmod -R a+rX "$PREFIX/include/oqs" "$PREFIX/lib/pkgconfig" 2>/dev/null || true

if [ "$PREFIX" = "/usr/local" ] || [ "$PREFIX" = "/usr" ]; then
    $SUDO ldconfig
    echo
    echo "liboqs $VERSION installed system-wide. Now just run:"
    echo "  make"
else
    echo
    echo "liboqs $VERSION installed to $PREFIX. Now run:"
    echo "  make PKG_CONFIG_PATH=\"$PREFIX/lib/pkgconfig\""
    echo "  LD_LIBRARY_PATH=\"$PREFIX/lib\" ./pq-sign list"
fi
