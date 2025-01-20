import pytest
from jasapp.rules.base_rule import BaseRule


class SEC0014(BaseRule):
    """
    Rule to detect if certificate validation is disabled with `wget` in `RUN` instructions.
    """
    rule_type = "dockerfile"

    def __init__(self):
        super().__init__(
            friendly_name="WgetCertValidationDisabled",
            name="SEC0014",
            description="`wget` command in `RUN` instruction is disabling certificate validation.",
            severity="error",
        )

    def check(self, instructions):
        """
        Checks if `wget` commands in `RUN` instructions are disabling certificate validation.

        Args:
            instructions (list): A list of dictionaries containing parsed Dockerfile instructions.

        Returns:
            list: A list of errors found, each as a dictionary with line, message, and severity.
        """
        errors = []

        for instr in instructions:
            if instr["instruction"] == "RUN":
                if self.is_wget_cert_validation_disabled(instr["arguments"]):
                    errors.append({
                        "line": instr["line"],
                        "message": "`wget` command in `RUN` instruction is disabling certificate validation. "
                                   "Use `--no-check-certificate` only if necessary and with caution.",
                        "severity": self.severity,
                        "doc_link": f"https://github.com/jassouline/jasapp/wiki/{self.name}"
                    })

        return errors

    def is_wget_cert_validation_disabled(self, command_string):
        """
        Checks if a command string contains a `wget` command that disables certificate validation.

        Args:
            command_string (str): The command string to check.

        Returns:
            bool: True if `wget` is used with options to disable cert validation, False otherwise.
        """
        if "wget" not in command_string:
            return False

        # Check for flags that disable certificate validation
        return "--no-check-certificate" in command_string


@pytest.fixture
def wget_cert_validation_disabled():
    return SEC0014()


def test_wget_cert_validation_disabled_detects_no_check_certificate(wget_cert_validation_disabled):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "wget --no-check-certificate https://example.com"},
    ]
    errors = wget_cert_validation_disabled.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "`wget` command in `RUN` instruction is disabling certificate validation" in errors[0]["message"]


def test_wget_cert_validation_disabled_allows_secure_wget(wget_cert_validation_disabled):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "wget https://example.com"},
    ]
    errors = wget_cert_validation_disabled.check(parsed_content)
    assert len(errors) == 0


def test_wget_cert_validation_disabled_ignores_other_instructions(wget_cert_validation_disabled):
    parsed_content = [
        {"line": 1, "instruction": "ENV", "arguments": "MY_VAR=value"},
    ]
    errors = wget_cert_validation_disabled.check(parsed_content)
    assert len(errors) == 0
