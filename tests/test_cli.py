"""Tests for CLI commands via Click CliRunner."""

import pytest
from click.testing import CliRunner

from deaddrop.cli import cli


@pytest.fixture
def runner():
    return CliRunner()


class TestCLIVersion:
    def test_version(self, runner):
        """Show version via CLI."""
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "1.2.0" in result.output


class TestCLICase:
    def test_case_create(self, runner):
        """Create a case via CLI."""
        result = runner.invoke(cli, ["case", "create", "--name", "CLI Test Case", "--analyst", "Tester"])
        assert result.exit_code == 0
        assert "CLI Test Case" in result.output
        assert "Tester" in result.output

    def test_case_list(self, runner):
        """List cases via CLI — should show table or 'no cases' message."""
        # First create a case so the list isn't empty
        runner.invoke(cli, ["case", "create", "--name", "List Test", "--analyst", "Tester"])
        result = runner.invoke(cli, ["case", "list"])
        assert result.exit_code == 0
        # Should show at least the case we just created
        assert "List Test" in result.output

    def test_case_info(self, runner):
        """Show case info via CLI."""
        # Create a case and capture its ID from output
        create_result = runner.invoke(cli, ["case", "create", "--name", "Info Test", "--analyst", "Alice"])
        assert create_result.exit_code == 0
        # Extract case ID from output (format: "✓ Case created: abc12345 — Info Test")
        output_lines = create_result.output.strip().split("\n")
        id_line = output_lines[0]
        # Parse the ID (between "created:" and "—")
        parts = id_line.split("created:")
        if len(parts) > 1:
            case_id = parts[1].strip().split(" ")[0].strip("—").strip()
            result = runner.invoke(cli, ["case", "info", case_id])
            assert result.exit_code == 0
            assert "Info Test" in result.output

    def test_case_close(self, runner):
        """Close a case via CLI."""
        create_result = runner.invoke(cli, ["case", "create", "--name", "Close Me"])
        # Extract case ID
        parts = create_result.output.split("created:")
        if len(parts) > 1:
            case_id = parts[1].strip().split(" ")[0].strip("—").strip()
            result = runner.invoke(cli, ["case", "close", case_id])
            assert result.exit_code == 0
            assert "closed" in result.output.lower()

    def test_case_info_not_found(self, runner):
        """Info for nonexistent case shows not found."""
        result = runner.invoke(cli, ["case", "info", "nonexistent"])
        assert result.exit_code == 0
        assert "not found" in result.output.lower()

    def test_case_close_not_found(self, runner):
        """Closing nonexistent case shows not found."""
        result = runner.invoke(cli, ["case", "close", "nonexistent"])
        assert result.exit_code == 0
        assert "not found" in result.output.lower()


class TestCLIIngest:
    def test_ingest_nonexistent_file(self, runner):
        """Ingesting a nonexistent file shows error."""
        # First create a case
        create_result = runner.invoke(cli, ["case", "create", "--name", "Ingest Test"])
        parts = create_result.output.split("created:")
        case_id = parts[1].strip().split(" ")[0].strip("—").strip() if len(parts) > 1 else "fake"

        result = runner.invoke(cli, ["ingest", "disk", "--image", "/nonexistent/file.raw", "--case", case_id])
        assert result.exit_code == 0
        assert "not found" in result.output.lower()

    def test_ingest_nonexistent_case(self, runner):
        """Ingesting to nonexistent case shows error."""
        result = runner.invoke(cli, ["ingest", "disk", "--image", "/tmp/test.raw", "--case", "nonexistent"])
        assert result.exit_code == 0
        assert "not found" in result.output.lower()


class TestCLIPlugin:
    def test_plugin_list(self, runner):
        """List plugins via CLI."""
        result = runner.invoke(cli, ["plugin", "list"])
        assert result.exit_code == 0
        # Should show built-in plugins or "No plugins found"
        assert "Plugins" in result.output or "No plugins" in result.output
