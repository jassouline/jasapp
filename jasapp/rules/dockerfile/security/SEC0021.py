import pytest
from jasapp.rules.base_rule import BaseRule


class SEC0021(BaseRule):
    """
    Rule to detect if the `rpm` package manager is configured to skip package signature checks in `RUN` instructions.
    """
    rule_type = "dockerfile"

    def __init__(self):
        super().__init__(
            friendly_name="RpmNoSignatureCheck",
            name="SEC0021",
            description="`rpm` is configured to skip package signature checks.",
            severity="error",
        )

    def check(self, instructions):
        """
        Checks if `rpm` commands in `RUN` instructions are configured to skip package signature checks.

        Args:
            instructions (list): A list of dictionaries containing parsed Dockerfile instructions.

        Returns:
            list: A list of errors found, each as a dictionary with line, message, and severity.
        """
        errors = []

        for instr in instructions:
            if instr["instruction"] == "RUN":
                if self.is_rpm_skipping_signature_check(instr["arguments"]):
                    errors.append({
                        "line": instr["line"],
                        "message": "`rpm` is configured to skip package signature checks. "
                                   "Avoid using `--nosignature` or similar options that bypass signature verification.",
                        "severity": self.severity,
                        "doc_link": f"https://github.com/jassouline/jasapp/wiki/{self.name}"
                    })

        return errors

    def is_rpm_skipping_signature_check(self, command_string):
        """
        Checks if a command string contains an `rpm` command that skips package signature checks.

        Args:
            command_string (str): The command string to check.

        Returns:
            bool: True if `rpm` is configured to skip signature checks, False otherwise.
        """
        if "rpm" not in command_string:
            return False

        # Check for flags that disable signature verification
        return "--nosignature" in command_string


@pytest.fixture
def rpm_skipping_signature_check():
    return SEC0021()


def test_rpm_signature_check_detects_nosignature(rpm_skipping_signature_check):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "rpm -i --nosignature package.rpm"},
    ]
    errors = rpm_skipping_signature_check.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "`rpm` is configured to skip package signature checks" in errors[0]["message"]


def test_rpm_signature_check_allows_secure_rpm(rpm_skipping_signature_check):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "rpm -i package.rpm"},
    ]
    errors = rpm_skipping_signature_check.check(parsed_content)
    assert len(errors) == 0


def test_rpm_signature_check_ignores_other_instructions(rpm_skipping_signature_check):
    parsed_content = [
        {"line": 1, "instruction": "ENV", "arguments": "MY_VAR=value"},
    ]
    errors = rpm_skipping_signature_check.check(parsed_content)
    assert len(errors) == 0
