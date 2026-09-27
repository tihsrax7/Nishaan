#!/usr/bin/env bash
# NISHAAN -- one command to start everything.
#   bash start.sh
# First time only, it installs what it needs (takes a few minutes).
# Then open http://localhost:8000 in your browser. Stop with Ctrl+C.
cd "$(dirname "$0")/backend" || exit 1

if ! python3 -c "import oqs, fastapi, uvicorn, cv2, pymupdf, jwt, Crypto, cryptography, multipart, requests" 2>/dev/null; then
  echo "First run: installing requirements (one time only)..."
  python3 -m pip install -r requirements.txt --break-system-packages || {
    echo; echo "Install failed. Copy the red error above and send it to your team."; exit 1; }
fi

echo
echo "  ============================================================"
echo "   NISHAAN is starting.  Open this in your browser:"
echo "        http://localhost:8000"
echo "   Keep this window open.  Press Ctrl+C here to stop."
echo "  ============================================================"
echo
exec python3 -m uvicorn app.main:app --host 127.0.0.1 --port 8000
