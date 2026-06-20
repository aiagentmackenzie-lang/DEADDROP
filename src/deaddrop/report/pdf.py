"""PDF export via WeasyPrint."""



def html_to_pdf(html_content: str, output_path: str) -> str:
    """Convert HTML string to PDF using WeasyPrint."""
    try:
        from weasyprint import HTML
        HTML(string=html_content).write_pdf(output_path)
        return output_path
    except ImportError as e:
        raise RuntimeError("weasyprint not installed. Install with: pip install weasyprint") from e
