import pytest
from jasapp.rules.base_rule import BaseRule


class SEC0026(BaseRule):
    """
    Rule to detect if `yum` configuration is modified to disable SSL verification in `RUN` instructions.
    """
    rule_type = "dockerfile"

    def __init__(self):
        super().__init__(
            friendly_name="YumDisableSSLVerify",
            name="SEC0026",
            description="`yum` is configured to disable SSL verification.",
            severity="error",
        )

    def check(self, instructions):
        """
        Checks if `yum` commands in `RUN` instructions are configured to disable SSL verification.

        Args:
            instructions (list): A list of dictionaries containing parsed Dockerfile instructions.

        Returns:
            list: A list of errors found, each as a dictionary with line, message, and severity.
        """
        errors = []

        for instr in instructions:
            if instr["instruction"] == "RUN":
                if self.is_yum_ssl_verification_disabled(instr["arguments"]):
                    errors.append({
                        "line": instr["line"],
                        "message": "`yum` is configured to disable SSL verification. "
                                   "Do not set `sslverify=false` in the `yum` configuration.",
                        "severity": self.severity,
                        "doc_link": f"https://github.com/jassouline/jasapp/wiki/{self.name}"
                    })

        return errors

    def is_yum_ssl_verification_disabled(self, command_string):
        """
        Checks if a command string contains a `yum` command that disables SSL verification.

        Args:
            command_string (str): The command string to check.

        Returns:
            bool: True if `yum` is configured to disable SSL verification, False otherwise.
        """
        if "yum" not in command_string:
            return False

        # Check for sslverify=false in the command
        return "sslverify=false" in command_string


@pytest.fixture
def yum_ssl_verification_disabled():
    return SEC0026()


def test_yum_ssl_verification_disabled_detects_disabled_verification(yum_ssl_verification_disabled):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "yum install -y --setopt=sslverify=false httpd"},
    ]
    errors = yum_ssl_verification_disabled.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "`yum` is configured to disable SSL verification" in errors[0]["message"]


def test_yum_ssl_verification_disabled_allows_enabled_verification(yum_ssl_verification_disabled):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "yum install -y httpd"},
    ]
    errors = yum_ssl_verification_disabled.check(parsed_content)
    assert len(errors) == 0


def test_yum_ssl_verification_disabled_ignores_other_commands(yum_ssl_verification_disabled):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "echo hello"},
    ]
    errors = yum_ssl_verification_disabled.check(parsed_content)
    assert len(errors) == 0


def test_yum_ssl_verification_disabled_ignores_other_instructions(yum_ssl_verification_disabled):
    parsed_content = [
        {"line": 1, "instruction": "ENV", "arguments": "MY_VAR=value"},
    ]
    errors = yum_ssl_verification_disabled.check(parsed_content)
    assert len(errors) == 0
