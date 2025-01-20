import pytest
from jasapp.rules.base_rule import BaseRule


class SEC0013(BaseRule):
    """
    Rule to detect if certificate validation is disabled with `curl` in `RUN` instructions.
    """
    rule_type = "dockerfile"

    def __init__(self):
        super().__init__(
            friendly_name="CurlCertValidationDisabled",
            name="SEC0013",
            description="`curl` command in `RUN` instruction is disabling certificate validation.",
            severity="error",
        )

    def check(self, instructions):
        """
        Checks if `curl` commands in `RUN` instructions are disabling certificate validation.

        Args:
            instructions (list): A list of dictionaries containing parsed Dockerfile instructions.

        Returns:
            list: A list of errors found, each as a dictionary with line, message, and severity.
        """
        errors = []

        for instr in instructions:
            if instr["instruction"] == "RUN":
                if self.is_curl_cert_validation_disabled(instr["arguments"]):
                    errors.append({
                        "line": instr["line"],
                        "message": "`curl` command in `RUN` instruction is disabling certificate validation. "
                                   "Use `--fail` or `-f` and `--insecure` or `-k` to ensure proper certificate validation.",
                        "severity": self.severity,
                        "doc_link": f"https://github.com/jassouline/jasapp/wiki/{self.name}"
                    })

        return errors

    def is_curl_cert_validation_disabled(self, command_string):
        """
        Checks if a command string contains a `curl` command that disables certificate validation.

        Args:
            command_string (str): The command string to check.

        Returns:
            bool: True if `curl` is used with insecure options, False otherwise.
        """
        if "curl" not in command_string:
            return False

        # Check for insecure flags without -f or --fail option
        return ("-k" in command_string or "--insecure" in command_string) and not ("-f" in command_string or "--fail" in command_string)


@pytest.fixture
def curl_cert_validation_disabled():
    return SEC0013()


def test_curl_cert_validation_disabled_detects_insecure_flag(curl_cert_validation_disabled):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "curl --insecure https://example.com"},
    ]
    errors = curl_cert_validation_disabled.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "`curl` command in `RUN` instruction is disabling certificate validation" in errors[0]["message"]


def test_curl_cert_validation_disabled_detects_k_flag(curl_cert_validation_disabled):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "curl -k https://example.com"},
    ]
    errors = curl_cert_validation_disabled.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "`curl` command in `RUN` instruction is disabling certificate validation" in errors[0]["message"]


def test_curl_cert_validation_disabled_allows_secure_flags(curl_cert_validation_disabled):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "curl --fail https://example.com"},
    ]
    errors = curl_cert_validation_disabled.check(parsed_content)
    assert len(errors) == 0

    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "curl -f https://example.com"},
    ]
    errors = curl_cert_validation_disabled.check(parsed_content)
    assert len(errors) == 0


def test_curl_cert_validation_disabled_ignores_other_instructions(curl_cert_validation_disabled):
    parsed_content = [
        {"line": 1, "instruction": "ENV", "arguments": "MY_VAR=value"},
    ]
    errors = curl_cert_validation_disabled.check(parsed_content)
    assert len(errors) == 0
