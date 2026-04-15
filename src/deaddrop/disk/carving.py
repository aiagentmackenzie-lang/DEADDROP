"""File carving — recover files by signature from raw disk images."""

import struct
from pathlib import Path
from dataclasses import dataclass

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


class FileCarver:
    """Carve files from raw disk images by matching header/footer signatures."""

    def __init__(self, chunk_size: int = 4096):
        self.chunk_size = chunk_size

    def carve(self, image_path: Path, output_dir: Path, max_files: int = 1000) -> list[dict]:
        """Scan a disk image for file signatures and carve out matches."""
        output_dir.mkdir(parents=True, exist_ok=True)
        results = []

        with open(image_path, "rb") as f:
            data = f.read()  # For now, read full image. TODO: streaming.

        for file_type, sig in SIGNATURES.items():
            if len(results) >= max_files:
                break

            offset = 0
            while offset < len(data) and len(results) < max_files:
                # Find header
                header_pos = data.find(sig["header"], offset)
                if header_pos == -1:
                    break

                # Find footer after header
                footer_pos = data.find(sig["footer"], header_pos + len(sig["header"]))
                if footer_pos == -1:
                    offset = header_pos + len(sig["header"])
                    continue

                # Calculate carved file size
                end_pos = footer_pos + len(sig["footer"])
                carved_size = end_pos - header_pos

                if carved_size > sig["max_size"]:
                    offset = header_pos + len(sig["header"])
                    continue

                # Extract and save
                carved_data = data[header_pos:end_pos]
                out_path = output_dir / f"carved_{file_type}_{header_pos:x}{sig['extension']}"
                out_path.write_bytes(carved_data)

                results.append({
                    "type": file_type,
                    "offset": header_pos,
                    "size": carved_size,
                    "output": str(out_path),
                })

                offset = end_pos

        return results