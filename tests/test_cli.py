from pathlib import Path
from typer.testing import CliRunner

from sentinel.cli import app

runner = CliRunner()


class TestCLI:
    def test_version(self):
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0

    def test_scan_nonexistent(self):
        result = runner.invoke(app, ["scan", "/nonexistent/path"])
        assert result.exit_code == 1

    def test_scan_clean_dir(self, tmp_path):
        (tmp_path / "clean.py").write_text("x = 1\n")
        result = runner.invoke(
            app,
            ["scan", str(tmp_path), "--format", "json"],
        )
        assert result.exit_code == 0

    def test_scan_buggy_dir(self, tmp_path):
        (tmp_path / "buggy.py").write_text('password = "secret123"\n')
        result = runner.invoke(
            app,
            ["scan", str(tmp_path), "--format", "json"],
        )
        assert result.exit_code == 0

    def test_rules_command(self):
        result = runner.invoke(app, ["rules"])
        assert result.exit_code == 0

    def test_verify_nonexistent(self):
        result = runner.invoke(app, ["verify", "/nonexistent.json"])
        assert result.exit_code == 1
