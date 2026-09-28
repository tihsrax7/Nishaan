"""
OWNER: Person C (watermark)
Two of the four layers from the full design:
  - pixel layer: DCT watermark in smooth/background 16x16 blocks
  - text layer: zero-width-character tag (used in PDF metadata)
Not built for the demo: layout (line/word shift) layer, bait layer,
Tardos collusion-secure codes, Reed-Solomon error correction.

v3 changes:
  - COLOUR is preserved: the mark goes only into the brightness (Y) channel
    of YCrCb, colour channels are untouched. Grayscale input still works.
  - FAST: all block DCT work is vectorised with numpy (no Python loop per
    block), ~50-100x faster than v2 on large images.
"""
import numpy as np
import cv2

B = 16                         # block size in pixels. 16 (not 8) so the mark survives
                               # "shrink to half size AND re-save as JPEG" leaks
P, Q = (2, 1), (1, 2)          # the two low/mid-frequency DCT coefficients we compare
SMOOTH_STD = 4                 # a block counts as "smooth background" below this std-dev
DELTA = 20.0                   # mark strength (same per-pixel visibility as 10 on 8x8)

# orthonormal B-point DCT-II basis (same convention as cv2.dct)
_C = np.array([[(np.sqrt(1 / B) if u == 0 else np.sqrt(2 / B)) * np.cos((2 * x + 1) * u * np.pi / (2 * B))
                for x in range(B)] for u in range(B)], dtype=np.float64)
_BASIS_P = np.outer(_C[P[0]], _C[P[1]])   # spatial pattern that coefficient P controls
_BASIS_Q = np.outer(_C[Q[0]], _C[Q[1]])


# ---------------------------------------------------------------- helpers
# Serif lettering for the visible marks, to match the console's Times New Roman look.
WM_FONT = cv2.FONT_HERSHEY_COMPLEX

def officer_to_bits(officer_id: int, n=16) -> list[int]:
    return [(officer_id >> (n - 1 - i)) & 1 for i in range(n)]


def bits_to_officer(bits) -> int:
    v = 0
    for b in bits:
        v = (v << 1) | int(b)
    return v


def _as_blocks(ch: np.ndarray) -> np.ndarray:
    """(H, W) -> (H//B, W//B, B, B) view of the full BxB blocks."""
    hh, ww = (ch.shape[0] // B) * B, (ch.shape[1] // B) * B
    return ch[:hh, :ww].reshape(hh // B, B, ww // B, B).swapaxes(1, 2)


def _smooth_block_coords(ref_y: np.ndarray):
    """Raster-order (row, col) block indices of smooth blocks in the reference."""
    blocks = _as_blocks(ref_y.astype(np.float64))
    mask = blocks.std(axis=(2, 3)) < SMOOTH_STD
    rows, cols = np.nonzero(mask)          # np.nonzero returns raster (row-major) order
    return rows, cols


def _pq(blocks_sel: np.ndarray):
    """DCT coefficients P and Q for a stack of BxB blocks, without a full DCT."""
    cp = np.einsum("nij,ij->n", blocks_sel, _BASIS_P)
    cq = np.einsum("nij,ij->n", blocks_sel, _BASIS_Q)
    return cp, cq


def to_luma(img: np.ndarray) -> np.ndarray:
    """Any page (gray or BGR/BGRA) -> brightness channel used for the mark."""
    if img.ndim == 2:
        return img
    if img.shape[2] == 4:
        img = cv2.cvtColor(img, cv2.COLOR_BGRA2BGR)
    return cv2.cvtColor(img, cv2.COLOR_BGR2YCrCb)[:, :, 0]


# ---------------------------------------------------------------- pixel layer
def _embed_y(y: np.ndarray, officer_id: int, key: int, delta: float, repeats: int) -> np.ndarray:
    bits = np.array(officer_to_bits(officer_id) * repeats)
    out = y.astype(np.float64).copy()
    rows, cols = _smooth_block_coords(y)
    nb = len(rows)
    if nb == 0:
        return y
    order = np.random.default_rng(key).permutation(nb)
    bit_for_block = np.empty(nb, dtype=np.int64)
    bit_for_block[order] = bits[np.arange(nb) % len(bits)]

    blocks = _as_blocks(out)                       # a view: writing into it writes into out
    sel = blocks[rows, cols]                       # (nb, B, B) copy
    cp, cq = _pq(sel)
    m = (cp + cq) / 2
    new_p, new_q = cp.copy(), cq.copy()
    one = (bit_for_block == 1) & (cp - cq < delta)
    zero = (bit_for_block == 0) & (cq - cp < delta)
    new_p[one], new_q[one] = m[one] + delta / 2, m[one] - delta / 2
    new_p[zero], new_q[zero] = m[zero] - delta / 2, m[zero] + delta / 2

    sel += (new_p - cp)[:, None, None] * _BASIS_P + (new_q - cq)[:, None, None] * _BASIS_Q
    # Pure-white (255) or pure-black (0) paper can't go brighter/darker, so the mark
    # would get clipped in half. Shift each such block's overall brightness by the
    # few levels needed (e.g. 255 -> 251, invisible). A flat shift changes only the
    # DC coefficient, so P and Q -- the mark -- are untouched.
    over = np.maximum(sel.max(axis=(1, 2)) - 255, 0)
    under = np.maximum(-sel.min(axis=(1, 2)), 0)
    sel += (under - over)[:, None, None]
    blocks[rows, cols] = sel
    return np.clip(np.rint(out), 0, 255).astype(np.uint8)


def embed_pixel(img: np.ndarray, officer_id: int, key=7, delta=DELTA, repeats=4) -> np.ndarray:
    """img: grayscale (H,W) or colour BGR (H,W,3). Returns the same kind of image,
    colours unchanged -- only brightness carries the mark."""
    if img.ndim == 2:
        return _embed_y(img, officer_id, key, delta, repeats)
    if img.shape[2] == 4:
        img = cv2.cvtColor(img, cv2.COLOR_BGRA2BGR)
    ycc = cv2.cvtColor(img, cv2.COLOR_BGR2YCrCb)
    ycc[:, :, 0] = _embed_y(ycc[:, :, 0], officer_id, key, delta, repeats)
    return cv2.cvtColor(ycc, cv2.COLOR_YCrCb2BGR)


def extract_pixel_detail(img: np.ndarray, ref: np.ndarray, key=7, n=16):
    """Returns (officer_id, confidence 0..1, blocks_used).
    ref: the ORIGINAL unmarked page (server keeps it per doc_id).
    img: suspect/leaked page, gray or colour, any size -- resized to ref first.
    confidence = how one-sided the block votes were, averaged over the 16 bits
    (1.0 = every block agreed; ~0 = noise, i.e. no NISHAAN mark found)."""
    ref_y = to_luma(ref)
    hh, ww = ref_y.shape
    sus_y = cv2.resize(to_luma(img), (ww, hh), interpolation=cv2.INTER_AREA).astype(np.float64)
    rows, cols = _smooth_block_coords(ref_y)
    nb = len(rows)
    if nb < n:
        return None, 0.0, nb
    order = np.random.default_rng(key).permutation(nb)
    sel = _as_blocks(sus_y)[rows, cols]
    cp, cq = _pq(sel)
    sign = np.where(cp > cq, 1, -1)
    slot = np.empty(nb, dtype=np.int64)
    slot[order] = np.arange(nb) % n                # which bit each block voted for
    votes = np.bincount(slot, weights=sign, minlength=n)
    per_bit = np.bincount(slot, minlength=n)
    conf = float(np.mean(np.abs(votes) / np.maximum(per_bit, 1)))
    return bits_to_officer([1 if v > 0 else 0 for v in votes]), conf, nb


def extract_pixel(img: np.ndarray, ref: np.ndarray, key=7, n=16) -> int:
    oid, _, _ = extract_pixel_detail(img, ref, key, n)
    return oid if oid is not None else 0


# ---------------------------------------------------------------- text layer
_ZW = {"0": "​", "1": "‌"}  # zero-width space / zero-width non-joiner


def tag_text(line: str, officer_id: int, at=5, n=16) -> str:
    code = "".join(_ZW[b] for b in format(officer_id, f"0{n}b"))
    return line[:at] + code + line[at:]


def read_text_tag(marked_line: str, n=16) -> int | None:
    zw = [c for c in marked_line if c in _ZW.values()]
    if len(zw) < n:
        return None
    bits = "".join("0" if c == _ZW["0"] else "1" for c in zw[:n])
    return int(bits, 2)


# ---------------------------------------------------------------- visible layer (deterrent)
def visible_stamp(img: np.ndarray, diag_text: str, footer_text: str, opacity: float = 0.13) -> np.ndarray:
    """Adds a VISIBLE watermark on top of an (already invisibly-marked) page:
      - faint diagonal text repeated across the whole page (the reader's name/copy no.)
      - a solid footer band stating who the copy belongs to, when and which session
    Called AFTER embed_pixel(), so the invisible mark's block layout still matches the
    stored original; the few blocks under the text just add noise to a majority vote."""
    gray = img.ndim == 2
    out = cv2.cvtColor(img, cv2.COLOR_GRAY2BGR) if gray else img.copy()
    if out.shape[2] == 4:
        out = cv2.cvtColor(out, cv2.COLOR_BGRA2BGR)
    h, w = out.shape[:2]

    # --- diagonal tiled text, drawn on a big canvas, rotated, then blended
    d = int((h * h + w * w) ** 0.5) + 20
    canvas = np.zeros((d, d), np.uint8)
    scale = max(0.6, min(w, h) / 900.0)
    thick = max(1, int(round(scale * 2)))
    (tw, th), _ = cv2.getTextSize(diag_text, WM_FONT, scale, thick)
    step_x, step_y = tw + int(120 * scale), th + int(150 * scale)
    for row, y in enumerate(range(th, d, step_y)):
        off = (row % 2) * (step_x // 2)
        for x in range(-step_x + off, d, step_x):
            cv2.putText(canvas, diag_text, (x, y), WM_FONT, scale, 255, thick, cv2.LINE_AA)
    rot = cv2.warpAffine(canvas, cv2.getRotationMatrix2D((d / 2, d / 2), 30, 1.0), (d, d))
    y0, x0 = (d - h) // 2, (d - w) // 2
    mask = rot[y0:y0 + h, x0:x0 + w].astype(np.float32) / 255.0 * opacity
    f = out.astype(np.float32)
    lum = cv2.cvtColor(out, cv2.COLOR_BGR2GRAY).astype(np.float32)
    ink = np.where(lum < 115, 235.0, 70.0)[..., None]             # light text on dark areas, dark text on light
    f = f * (1 - mask[..., None]) + ink * mask[..., None]

    # --- footer band
    fs = max(0.45, w / 2200.0)
    ft = max(1, int(round(fs * 2)))
    (_, fh), _ = cv2.getTextSize(footer_text, WM_FONT, fs, ft)
    band = fh + int(22 * fs + 10)
    f[h - band:h, :] = f[h - band:h, :] * 0.15 + np.array([40, 30, 12], np.float32) * 0.85   # deep teal-ink band
    out = np.clip(f, 0, 255).astype(np.uint8)
    # shrink footer text until it fits the width
    while cv2.getTextSize(footer_text, WM_FONT, fs, ft)[0][0] > w - 24 and fs > 0.3:
        fs -= 0.03
    cv2.putText(out, footer_text, (12, h - band // 2 + fh // 2), WM_FONT, fs, (255, 255, 255), ft, cv2.LINE_AA)
    return cv2.cvtColor(out, cv2.COLOR_BGR2GRAY) if gray else out
