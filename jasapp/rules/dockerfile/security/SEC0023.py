import re
import pytest
from jasapp.rules.base_rule import BaseRule


class SEC0023(BaseRule):
    """
    Rule to detect if the `npm` configuration disables strict SSL verification in `RUN` instructions.
    """
    rule_type = "dockerfile"

    def __init__(self):
        super().__init__(
            friendly_name="NpmConfigDisablesStrictSSL",
            name="SEC0023",
            description="`npm config set strict-ssl false` is used, which disables strict SSL verification.",
            severity="error",
        )

    def check(self, instructions):
        """
        Checks if `npm config` commands in `RUN` instructions disable strict SSL.

        Args:
            instructions (list): A list of dictionaries containing parsed Dockerfile instructions.

        Returns:
            list: A list of errors found, each as a dictionary with line, message, and severity.
        """
        errors = []

        for instr in instructions:
            if instr["instruction"] == "RUN":
                if self.is_npm_disabling_strict_ssl(instr["arguments"]):
                    errors.append({
                        "line": instr["line"],
                        "message": "`npm config set strict-ssl false` is used, which disables strict SSL verification.",
                        "severity": self.severity,
                        "doc_link": f"https://github.com/jassouline/jasapp/wiki/{self.name}"
                    })

        return errors

    def is_npm_disabling_strict_ssl(self, command_string):
        """
        Checks if a command string contains an `npm config` command that disables strict SSL.

        Args:
            command_string (str): The command string to check.

        Returns:
            bool: True if `npm config` disables strict SSL, False otherwise.
        """
        if "npm" not in command_string or "config" not in command_string:
            return False

        # Check for npm config set strict-ssl false, ignoring leading/trailing spaces and quotes
        match = re.search(r"npm\s+config\s+set\s+strict-ssl\s+false", command_string, re.IGNORECASE)

        return bool(match)


@pytest.fixture
def npm_config_disables_strict_ssl():
    return SEC0023()


def test_npm_config_disables_strict_ssl_detects_disabled(npm_config_disables_strict_ssl):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "npm config set strict-ssl false"},
    ]
    errors = npm_config_disables_strict_ssl.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "`npm config set strict-ssl false` is used" in errors[0]["message"]


def test_npm_config_disables_strict_ssl_allows_enabled(npm_config_disables_strict_ssl):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "npm config set strict-ssl true"},
    ]
    errors = npm_config_disables_strict_ssl.check(parsed_content)
    assert len(errors) == 0


def test_npm_config_disables_strict_ssl_ignores_other_commands(npm_config_disables_strict_ssl):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "echo hello"},
    ]
    errors = npm_config_disables_strict_ssl.check(parsed_content)
    assert len(errors) == 0


def test_npm_config_disables_strict_ssl_ignores_other_instructions(npm_config_disables_strict_ssl):
    parsed_content = [
        {"line": 1, "instruction": "ENV", "arguments": "MY_VAR=value"},
    ]
    errors = npm_config_disables_strict_ssl.check(parsed_content)
    assert len(errors) == 0
