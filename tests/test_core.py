from sentinel import scan_source, scan_directory, scan_file, Finding, Severity, Category


class TestScanSource:
    def test_scan_clean_code(self):
        report = scan_source("x = 1\n", "clean.py")
        assert report.path == "clean.py"
        assert len(report.findings) == 0

    def test_scan_sql_injection(self):
        code = 'query = f"SELECT * FROM users WHERE id = {user_id}"\ncursor.execute(query)\n'
        report = scan_source(code, "test.py")
        rules = [f.rule for f in report.findings]
        assert "sql-injection" in rules

    def test_scan_shell_injection(self):
        code = 'subprocess.run(user_input, shell=True)\n'
        report = scan_source(code, "test.py")
        rules = [f.rule for f in report.findings]
        assert "subprocess-shell-true" in rules

    def test_scan_hardcoded_secrets(self):
        code = 'password = "secret123"\n'
        report = scan_source(code, "test.py")
        rules = [f.rule for f in report.findings]
        assert "hardcoded-secret" in rules

    def test_scan_bare_except(self):
        code = "try:\n    x = 1\nexcept:\n    pass\n"
        report = scan_source(code, "test.py")
        rules = [f.rule for f in report.findings]
        assert "bare-except" in rules

    def test_scan_eval(self):
        code = 'result = eval(user_input)\n'
        report = scan_source(code, "test.py")
        rules = [f.rule for f in report.findings]
        assert "use-of-eval" in rules


class TestScanFile:
    def test_scan_fixture(self):
        from pathlib import Path

        fixture = Path(__file__).parent / "fixtures" / "sql_injection.py"
        if fixture.exists():
            report = scan_file(str(fixture), fixture.read_text())
            assert len(report.findings) > 0


class TestScanDirectory:
    def test_scan_fixtures_dir(self):
        from pathlib import Path

        fixtures_dir = Path(__file__).parent / "fixtures"
        if fixtures_dir.exists():
            report = scan_directory(str(fixtures_dir))
            assert report.summary.total_files > 0
            assert report.summary.total_findings > 0


class TestModels:
    def test_severity_str(self):
        assert str(Severity.Error) == "error"
        assert str(Severity.Warning) == "warning"
        assert str(Severity.Info) == "info"

    def test_category_str(self):
        assert str(Category.Security) == "security"
        assert str(Category.Compliance) == "compliance"

    def test_finding_has_id(self):
        f = Finding(
            id="test-1",
            rule="test-rule",
            severity=Severity.Error,
            category=Category.Security,
            file="test.py",
            line=1,
            column=0,
            message="test",
            suggestion="fix it",
            confidence=0.9,
        )
        assert f.id == "test-1"
        assert f.severity == Severity.Error
