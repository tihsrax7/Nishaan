#!/usr/bin/env bash
# NISHAAN -- one command to start everything.
#   bash start.sh
# First time only, it installs what it needs (takes a few minutes).
# Air-gapped machine? Build offline_bundle/ first (tools/make_offline_bundle.sh) -- then nothing is downloaded.
# Then open http://localhost:8000 in your browser. Stop with Ctrl+C.
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT/backend" || exit 1

# offline bundle: use its liboqs library and its Python packages (no internet needed)
if [ -d "$ROOT/offline_bundle/liboqs" ] && [ -z "$OQS_INSTALL_PATH" ]; then
  export OQS_INSTALL_PATH="$ROOT/offline_bundle/liboqs"
fi

if ! python3 -c "import oqs, fastapi, uvicorn, cv2, pymupdf, jwt, Crypto, cryptography, multipart, requests" 2>/dev/null; then
  if [ -d "$ROOT/offline_bundle/wheels" ]; then
    echo "First run: installing requirements from the OFFLINE bundle (no internet used)..."
    python3 -m pip install --no-index --find-links "$ROOT/offline_bundle/wheels" -r requirements.txt --break-system-packages || {
      echo; echo "Offline install failed. Copy the red error above and send it to your team."; exit 1; }
  else
    echo "First run: installing requirements (one time only)..."
    python3 -m pip install -r requirements.txt --break-system-packages || {
      echo; echo "Install failed. Copy the red error above and send it to your team."; exit 1; }
  fi
fi

echo
echo "  ============================================================"
echo "   NISHAAN is starting.  Open this in your browser:"
echo "        http://localhost:8000"
echo "   Runs fully offline: no cloud, no public blockchain."
echo "   Keep this window open.  Press Ctrl+C here to stop."
echo "  ============================================================"
echo
exec python3 -m uvicorn app.main:app --host 127.0.0.1 --port 8000
