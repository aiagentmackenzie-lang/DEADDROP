"""Tests for FileCarver — stream-based file recovery."""

from pathlib import Path

import pytest

from deaddrop.disk.carving import FileCarver


@pytest.fixture
def carver():
    return FileCarver(chunk_size=4096)


@pytest.fixture
def output_dir(tmp_path):
    d = tmp_path / "carved"
    d.mkdir()
    return d


class TestFileCarver:
    def test_carve_jpeg(self, tmp_path, output_dir):
        """Carve a JPEG file embedded in a larger binary blob."""
        image = tmp_path / "image.raw"
        # Build: garbage + JPEG + garbage
        jpeg_data = b"\xff\xd8\xff\xe0" + b"\x00" * 100 + b"\xff\xd9"
        data = b"\x00" * 512 + jpeg_data + b"\x00" * 512
        image.write_bytes(data)

        carver = FileCarver()
        results = carver.carve(image, output_dir)
        assert len(results) == 1
        assert results[0]["type"] == "JPEG"
        assert results[0]["size"] == len(jpeg_data)
        assert Path(results[0]["output"]).exists()
        assert Path(results[0]["output"]).read_bytes() == jpeg_data

    def test_carve_png(self, tmp_path, output_dir):
        """Carve a PNG file from a binary blob."""
        image = tmp_path / "image.raw"
        png_data = b"\x89PNG\r\n\x1a\n" + b"\x00" * 50 + b"IEND\xaeB`\x82"
        data = b"\xcc" * 256 + png_data + b"\xcc" * 256
        image.write_bytes(data)

        carver = FileCarver()
        results = carver.carve(image, output_dir)
        assert len(results) == 1
        assert results[0]["type"] == "PNG"
        assert Path(results[0]["output"]).exists()

    def test_carve_no_signatures(self, tmp_path, output_dir):
        """Return empty results when no signatures found."""
        image = tmp_path / "blank.raw"
        image.write_bytes(b"\x00" * 4096)

        carver = FileCarver()
        results = carver.carve(image, output_dir)
        assert results == []

    def test_carve_multiple_types(self, tmp_path, output_dir):
        """Carve both JPEG and PNG from the same image."""
        image = tmp_path / "image.raw"
        jpeg_data = b"\xff\xd8\xff" + b"\x00" * 50 + b"\xff\xd9"
        png_data = b"\x89PNG\r\n\x1a\n" + b"\x00" * 50 + b"IEND\xaeB`\x82"
        data = jpeg_data + b"\x00" * 64 + png_data + b"\x00" * 64
        image.write_bytes(data)

        carver = FileCarver()
        results = carver.carve(image, output_dir)
        assert len(results) == 2
        types = {r["type"] for r in results}
        assert "JPEG" in types
        assert "PNG" in types

    def test_max_files_limit(self, tmp_path, output_dir):
        """Respect max_files limit."""
        image = tmp_path / "image.raw"
        # Create image with many JPEGs
        jpeg = b"\xff\xd8\xff" + b"\x00" * 20 + b"\xff\xd9"
        data = jpeg * 10
        image.write_bytes(data)

        carver = FileCarver()
        results = carver.carve(image, output_dir, max_files=3)
        assert len(results) <= 3

    def test_carve_pdf(self, tmp_path, output_dir):
        """Carve a PDF file."""
        image = tmp_path / "image.raw"
        pdf_data = b"%PDF-1.4" + b"\x00" * 100 + b"%%EOF"
        data = b"\xab" * 128 + pdf_data + b"\xab" * 128
        image.write_bytes(data)

        carver = FileCarver()
        results = carver.carve(image, output_dir)
        assert len(results) == 1
        assert results[0]["type"] == "PDF"

    def test_output_dir_created(self, tmp_path):
        """Output directory is created if it doesn't exist."""
        image = tmp_path / "test.raw"
        image.write_bytes(b"\xff\xd8\xff" + b"\x00" * 10 + b"\xff\xd9")
        output_dir = tmp_path / "new_dir" / "subdir"

        carver = FileCarver()
        carver.carve(image, output_dir)
        assert output_dir.exists()

    def test_empty_image(self, tmp_path, output_dir):
        """Empty image returns no results."""
        image = tmp_path / "empty.raw"
        image.write_bytes(b"")

        carver = FileCarver()
        results = carver.carve(image, output_dir)
        assert results == []
