"""File carving — recover files by signature from raw disk images."""

from pathlib import Path

# Common file signatures (magic bytes + footer for carving)
SIGNATURES = {
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
        "footer": b"\x00\x3b",
        "extension": ".gif",
        "max_size": 20 * 1024 * 1024,
    },
    "ZIP": {
        "header": b"PK\x03\x04",
        "footer": b"PK\x05\x06",
        "extension": ".zip",
        "max_size": 500 * 1024 * 1024,
    },
    "DOCX": {
        "header": b"PK\x03\x04",
        "footer": b"PK\x05\x06",
        "extension": ".docx",
        "max_size": 100 * 1024 * 1024,
    },
}

# Default read chunk size for streaming carve (4MB — reasonable for most images)
DEFAULT_CHUNK_SIZE = 4 * 1024 * 1024


class FileCarver:
    """Carve files from raw disk images by matching header/footer signatures.

    Uses streaming reads to avoid loading entire images into RAM.
    """

    def __init__(self, chunk_size: int = DEFAULT_CHUNK_SIZE):
        self.chunk_size = chunk_size

    def carve(self, image_path: Path, output_dir: Path, max_files: int = 1000) -> list[dict]:
        """Scan a disk image for file signatures and carve out matches.

        Streams the image in chunks to avoid loading it all into RAM.
        Uses an overlap buffer at chunk boundaries to catch signatures
        that span across chunk borders.
        """
        output_dir.mkdir(parents=True, exist_ok=True)
        results = []
        image_size = image_path.stat().st_size

        # Overlap must be >= longest signature (header or footer)
        # to catch patterns spanning chunk boundaries
        max_sig_len = max(
            max(len(s["header"]), len(s["footer"]))
            for s in SIGNATURES.values()
        )
        overlap_size = max_sig_len

        with open(image_path, "rb") as f:
            carry = b""
            file_offset = 0  # absolute position in the image

            while file_offset < image_size and len(results) < max_files:
                # Read next chunk + carry from previous
                raw = f.read(self.chunk_size)
                if not raw:
                    break

                data = carry + raw
                data_start = file_offset - len(carry)  # absolute start of `data`

                # Scan for all signature types in this data block
                for file_type, sig in SIGNATURES.items():
                    if len(results) >= max_files:
                        break

                    pos = 0
                    while pos < len(data) and len(results) < max_files:
                        header_pos = data.find(sig["header"], pos)
                        if header_pos == -1:
                            break  # No more headers of this type in this chunk

                        abs_header = data_start + header_pos

                        # Look for footer after header
                        footer_search = header_pos + len(sig["header"])
                        footer_pos = data.find(sig["footer"], footer_search)

                        if footer_pos != -1:
                            # Found header + footer in this chunk
                            end_pos = footer_pos + len(sig["footer"])
                            carved_size = end_pos - header_pos

                            if carved_size <= sig["max_size"]:
                                carved_data = data[header_pos:end_pos]
                                out_path = output_dir / f"carved_{file_type}_{abs_header:x}{sig['extension']}"
                                out_path.write_bytes(carved_data)

                                results.append({
                                    "type": file_type,
                                    "offset": abs_header,
                                    "size": carved_size,
                                    "output": str(out_path),
                                })

                            pos = footer_pos + len(sig["footer"])
                        else:
                            # Footer not found in this chunk.
                            # For simplicity, skip — a full implementation would
                            # continue reading to find the footer.
                            pos = header_pos + len(sig["header"])

                # Carry overlap bytes for next iteration
                if len(data) > overlap_size:
                    carry = data[-overlap_size:]
                    file_offset += len(raw)
                else:
                    # Small final chunk — nothing more to read
                    carry = b""
                    file_offset += len(raw)

        return results