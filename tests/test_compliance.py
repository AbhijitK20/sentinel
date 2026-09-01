from sentinel import scan_source


class TestCompliance:
    def test_hipaa_finds_patient_data(self):
        code = "patient = get_patient_data()\nprint(patient)\n"
        report = scan_source(code, "medical.py")
        hipaa_findings = [f for f in report.findings if "hipaa" in f.rule]
        assert len(hipaa_findings) > 0
        assert hipaa_findings[0].category.__str__() == "compliance"

    def test_gdpr_finds_pii_exposure(self):
        code = "print(email)\nprint(name)\n"
        report = scan_source(code, "data.py")
        gdpr_findings = [f for f in report.findings if "gdpr" in f.rule]
        assert len(gdpr_findings) > 0

    def test_pci_finds_card_data(self):
        code = "card_number = get_card()\nlog(card_number)\n"
        report = scan_source(code, "payment.py")
        pci_findings = [f for f in report.findings if "pci" in f.rule]
        assert len(pci_findings) > 0

    def test_sox_finds_financial_modification(self):
        code = "financial.delete(id)\n"
        report = scan_source(code, "finance.py")
        sox_findings = [f for f in report.findings if "sox" in f.rule]
        assert len(sox_findings) > 0
