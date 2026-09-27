"""
OWNER: Person C (watermark) or whoever picks up PDF support
Lets /share and /open work on real PDFs, not just PNG/JPG page images.
Approach: render every PDF page to a COLOUR image, watermark each page's
brightness channel (colours unchanged), then rebuild a
single output PDF from the watermarked pages. Also stamps the officer's
zero-width text tag into the PDF's Subject metadata field as a second,
independent trace path (in case someone strips or blurs the visible pages
but keeps/copies the file's metadata or properties panel text).
"""
import io
import pymupdf  # aka fitz
import numpy as np
import cv2

from . import watermark

RENDER_DPI = 150


def is_pdf(filename: str, data: bytes) -> bool:
    return filename.lower().endswith(".pdf") or data[:4] == b"%PDF"


def pdf_to_pages(data: bytes) -> list[np.ndarray]:
    """PDF bytes -> list of colour (BGR) page images (numpy arrays)."""
    doc = pymupdf.open(stream=data, filetype="pdf")
    pages = []
    zoom = RENDER_DPI / 72
    mat = pymupdf.Matrix(zoom, zoom)
    for page in doc:
        pix = page.get_pixmap(matrix=mat, colorspace=pymupdf.csRGB, alpha=False)
        rgb = np.frombuffer(pix.samples, dtype=np.uint8).reshape(pix.height, pix.width, 3)
        pages.append(cv2.cvtColor(rgb, cv2.COLOR_RGB2BGR))
    doc.close()
    return pages


def pages_to_pdf(pages: list[np.ndarray], officer_id: int, tag_text: str | None = None,
                 title: str = "NISHAAN secured document") -> bytes:
    """Watermarked page images -> a single output PDF.
    Also writes the officer's zero-width tag into the Subject metadata field
    (the text-layer trace path) -- invisible in any normal PDF viewer."""
    doc = pymupdf.open()
    for img in pages:
        # JPEG q=92, not PNG: ~20x smaller output (a 31-page PDF was ~195 MB as PNG).
        # The pixel mark is built to survive JPEG, so tracing is unaffected.
        ok, buf = cv2.imencode(".jpg", img, [cv2.IMWRITE_JPEG_QUALITY, 92])
        page_w, page_h = img.shape[1] * 72 / RENDER_DPI, img.shape[0] * 72 / RENDER_DPI
        page = doc.new_page(width=page_w, height=page_h)
        page.insert_image(pymupdf.Rect(0, 0, page_w, page_h), stream=buf.tobytes())

    subject = tag_text or watermark.tag_text(f"NISHAAN copy for officer #{officer_id:02d}", officer_id)
    doc.set_metadata({"subject": subject, "title": title, "producer": "NISHAAN", "creator": "NISHAAN"})
    out = doc.tobytes(garbage=3, deflate=True)
    doc.close()
    return out


def read_pdf_metadata_tag(data: bytes) -> int | None:
    """Extract the officer id hidden in the Subject field of a (possibly leaked) PDF."""
    doc = pymupdf.open(stream=data, filetype="pdf")
    subject = doc.metadata.get("subject", "") or ""
    doc.close()
    return watermark.read_text_tag(subject)
