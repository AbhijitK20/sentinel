from sentinel import scan_source


class TestEvidence:
    def test_sql_injection_has_evidence(self):
        code = 'query = f"SELECT * FROM users WHERE id = {user_id}"\ncursor.execute(query)\n'
        report = scan_source(code, "test.py")
        sql_findings = [f for f in report.findings if f.rule == "sql-injection"]
        assert len(sql_findings) > 0
        assert sql_findings[0].evidence is not None
        assert sql_findings[0].evidence.proof_type == "behavioral"
        assert "reproduction" in sql_findings[0].evidence.reproduction_code.lower() or "import" in sql_findings[0].evidence.reproduction_code.lower()

    def test_shell_injection_has_evidence(self):
        code = 'subprocess.run(user_input, shell=True)\n'
        report = scan_source(code, "test.py")
        shell_findings = [f for f in report.findings if f.rule == "subprocess-shell-true"]
        assert len(shell_findings) > 0
        assert shell_findings[0].evidence is not None

    def test_mutable_default_has_evidence(self):
        code = "def f(x=[]):\n    x.append(1)\n"
        report = scan_source(code, "test.py")
        mutable_findings = [f for f in report.findings if f.rule == "mutable-default-argument"]
        assert len(mutable_findings) > 0
        assert mutable_findings[0].evidence is not None

    def test_except_pass_has_evidence(self):
        code = "try:\n    x = 1\nexcept:\n    pass\n"
        report = scan_source(code, "test.py")
        pass_findings = [f for f in report.findings if f.rule == "except-pass"]
        assert len(pass_findings) > 0
        assert pass_findings[0].evidence is not None
