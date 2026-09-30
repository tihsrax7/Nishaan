#!/usr/bin/env bash
# NISHAAN -- build an OFFLINE install bundle (for air-gapped machines).
#
# Run this ONCE on a machine that HAS internet and the SAME operating system + Python
# version as the air-gapped target (e.g. your Ubuntu/WSL laptop):
#     bash tools/make_offline_bundle.sh
# Then copy the whole NISHAAN folder (including offline_bundle/) to the air-gapped machine
# and run  bash start.sh  there as usual. Nothing is downloaded on the target.
set -e
cd "$(dirname "$0")/.."
OUT="offline_bundle"
mkdir -p "$OUT/wheels"

echo "1/2  Downloading Python packages into $OUT/wheels ..."
python3 -m pip download -r backend/requirements.txt -d "$OUT/wheels"

echo "2/2  Adding the liboqs library (post-quantum crypto) ..."
rm -rf "$OUT/liboqs"
if [ -d "$HOME/_oqs/lib" ] || [ -d "$HOME/_oqs/lib64" ]; then
  cp -r "$HOME/_oqs" "$OUT/liboqs"                       # built automatically on first run
else
  LIB=$(ldconfig -p 2>/dev/null | awk '/liboqs\.so/{print $NF; exit}')
  if [ -n "$LIB" ]; then
    mkdir -p "$OUT/liboqs/lib"
    cp -P "$(dirname "$LIB")"/liboqs.so* "$OUT/liboqs/lib/"
  else
    echo "   liboqs not found locally: building it (needs git + cmake + a C compiler) ..."
    TMP=$(mktemp -d)
    git clone --depth 1 --branch 0.16.0 https://github.com/open-quantum-safe/liboqs "$TMP/liboqs"
    cmake -S "$TMP/liboqs" -B "$TMP/liboqs/build" -DBUILD_SHARED_LIBS=ON -DOQS_BUILD_ONLY_LIB=ON \
          -DCMAKE_INSTALL_PREFIX="$PWD/$OUT/liboqs"
    cmake --build "$TMP/liboqs/build" --parallel 4
    cmake --build "$TMP/liboqs/build" --target install
    rm -rf "$TMP"
  fi
fi
echo
echo "Offline bundle ready in ./$OUT  ($(du -sh "$OUT" | cut -f1))."
echo "Copy the whole folder to the air-gapped machine and run: bash start.sh"
