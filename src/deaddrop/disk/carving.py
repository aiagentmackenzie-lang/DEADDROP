"""File carving — recover files by signature from raw disk images.

Stateful cross-chunk carving (SB-9 fix). The prior implementation carried only
a tiny overlap buffer (longest signature, ~8 bytes) between chunks, so any file
whose header was more than 8 bytes before the chunk end and whose footer fell
in the next chunk was silently dropped — a chain-of-custody integrity bug for a
court-grade DFIR tool. This version scans for headers, then keeps reading (with
a bounded accumulator) until the footer is found or max_size is exceeded, so
files spanning any chunk boundary are carved.
"""

from __future__ import annotations

from pathlib import Path
from typing import TypedDict


class FileSignature(TypedDict):
    header: bytes
    footer: bytes
    extension: str
    max_size: int


# Common file signatures (magic bytes + footer for carving)
SIGNATURES: dict[str, FileSignature] = {
    "JPEG": {
        "header": b"\xff\xd8\xff",
        "footer": b"\xff\xd9",
        "extension": ".jpg",
        "max_size": 50 * 1024 * 1024,  # 50MB
    },
    "PNG": {
        "header": b"\x89PNG\r\n\x1a\n",
        "footer": b"IEND\xaeB`\x82",
        "extension": ".png",
        "max_size": 50 * 1024 * 1024,
    },
    "PDF": {
        "header": b"%PDF",
        "footer": b"%%EOF",
        "extension": ".pdf",
        "max_size": 100 * 1024 * 1024,
    },
    "GIF": {
        "header": b"GIF8",
        "footer": b"\x3b",
        "extension": ".gif",
        "max_size": 20 * 1024 * 1024,
    },
    "ZIP": {
        "header": b"PK\x03\x04",
        "footer": b"PK\x05\x06",
        "extension": ".zip",
        "max_size": 500 * 1024 * 1024,
    },
    # NOTE: DOCX/DOC/PPTX/XLSX are ZIP-based (same PK header/footer). They cannot
    # be distinguished from ZIP by signature alone. Carved as .zip; analysts can
    # inspect content to identify Office docs.
}

# Streaming read chunk size (4MB — reasonable for most images)
DEFAULT_CHUNK_SIZE = 4 * 1024 * 1024


class FileCarver:
    """Carve files from raw disk images by matching header/footer signatures.

    Uses a streaming scan that continues reading past chunk boundaries when a
    header is found, so files whose footer lies in a later chunk are recovered
    (bounded by each signature's max_size to avoid runaway memory).
    """

    def __init__(self, chunk_size: int = DEFAULT_CHUNK_SIZE):
        self.chunk_size = chunk_size

    def carve(self, image_path: Path, output_dir: Path, max_files: int = 1000) -> list[dict]:
        """Scan a disk image for file signatures and carve out matches.

        Streams the image. For each header found, reads forward (accumulating
        into a bounded buffer) until the footer is found or the signature's
        max_size is exceeded — so cross-chunk files are recovered.
        """
        output_dir.mkdir(parents=True, exist_ok=True)
        results: list[dict] = []
        image_size = image_path.stat().st_size
        if image_size == 0:
            return results

        # Precompute header bytes for fast multi-pattern scanning.
        headers = [(name, sig["header"]) for name, sig in SIGNATURES.items()]

        with open(image_path, "rb") as f:
            offset = 0
            while offset < image_size and len(results) < max_files:
                chunk = f.read(self.chunk_size)
                if not chunk:
                    break

                # Scan this chunk for every signature's header.
                search_base = offset
                # Track how far we've consumed so we don't re-scan within a chunk
                # after returning from a multi-chunk carve.
                cursor = 0
                while cursor < len(chunk) and len(results) < max_files:
                    # Find the next header of any type at/after cursor.
                    best_pos = -1
                    best_type: str | None = None
                    best_header_len = 0
                    for name, header in headers:
                        pos = chunk.find(header, cursor)
                        if pos != -1 and (best_pos == -1 or pos < best_pos):
                            best_pos = pos
                            best_type = name
                            best_header_len = len(header)
                    if best_pos == -1 or best_type is None:
                        break  # no more headers in this chunk

                    abs_header = search_base + best_pos
                    sig = SIGNATURES[best_type]
                    # Try to carve starting at this header, reading across chunk
                    # boundaries as needed. Returns the bytes carved (or None)
                    # and the absolute file offset where the footer ended.
                    carved, footer_end_abs = self._carve_one(
                        f, image_path, abs_header, best_header_len, sig, image_size
                    )
                    if carved is not None and footer_end_abs is not None:
                        out_path = output_dir / (
                            f"carved_{best_type}_{abs_header:x}{sig['extension']}"
                        )
                        out_path.write_bytes(carved)
                        results.append({
                            "type": best_type,
                            "offset": abs_header,
                            "size": len(carved),
                            "output": str(out_path),
                        })
                        # Advance the file cursor past the footer; reload chunk.
                        f.seek(footer_end_abs)
                        offset = footer_end_abs
                        chunk = f.read(self.chunk_size)
                        search_base = offset
                        cursor = 0
                    else:
                        # Footer not found within max_size — skip this header,
                        # continue scanning the rest of the current chunk.
                        cursor = best_pos + best_header_len
                        f.seek(search_base + len(chunk))  # restore EOF pos
                        offset = search_base + len(chunk)
                else:
                    # cursor loop exhausted the chunk normally
                    offset = search_base + len(chunk)

        return results

    def _carve_one(
        self,
        f,
        image_path: Path,
        header_abs: int,
        header_len: int,
        sig: FileSignature,
        image_size: int,
    ) -> tuple[bytes | None, int | None]:
        """Read from header_abs until the footer is found or max_size exceeded.

        Returns (carved_bytes, footer_end_abs) or (None, None) if no footer
        within max_size. Seeks the file back to the end of the carve region on
        return so the caller can resume scanning. Memory is bounded by
        max_size per file.
        """
        max_size = sig["max_size"]
        footer = sig["footer"]
        # Don't read past EOF.
        end_limit = min(header_abs + max_size, image_size)

        f.seek(header_abs)
        accumulator = bytearray()
        while f.tell() < end_limit:
            read = f.read(min(self.chunk_size, end_limit - f.tell()))
            if not read:
                break
            accumulator.extend(read)
            # Search the accumulated bytes for the footer (after the header).
            footer_pos = accumulator.find(footer, header_len)
            if footer_pos != -1:
                end = footer_pos + len(footer)
                carved = bytes(accumulator[:end])
                footer_end_abs = header_abs + end
                return carved, footer_end_abs

        # Footer not found within max_size — give up on this header.
        return None, None
