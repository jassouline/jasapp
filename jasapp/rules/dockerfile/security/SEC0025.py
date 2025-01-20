import re
import pytest
from jasapp.rules.base_rule import BaseRule


class SEC0025(BaseRule):
    """
    Rule to detect if `git` is configured to disable SSL verification in `RUN` instructions.
    """
    rule_type = "dockerfile"

    def __init__(self):
        super().__init__(
            friendly_name="GitDisableSSLVerify",
            name="SEC0025",
            description="`git` is configured to disable SSL verification.",
            severity="error",
        )

    def check(self, instructions):
        """
        Checks if `git` commands in `RUN` instructions are configured to disable SSL verification.

        Args:
            instructions (list): A list of dictionaries containing parsed Dockerfile instructions.

        Returns:
            list: A list of errors found, each as a dictionary with line, message, and severity.
        """
        errors = []

        for instr in instructions:
            if instr["instruction"] == "RUN":
                if self.is_git_ssl_verification_disabled(instr["arguments"]):
                    errors.append({
                        "line": instr["line"],
                        "message": "`git` is configured to disable SSL verification. "
                                   "Do not use `git config --global http.sslVerify false`.",
                        "severity": self.severity,
                        "doc_link": f"https://github.com/jassouline/jasapp/wiki/{self.name}"
                    })

        return errors

    def is_git_ssl_verification_disabled(self, command_string):
        """
        Checks if a command string contains a `git config` command that disables SSL verification.

        Args:
            command_string (str): The command string to check.

        Returns:
            bool: True if `git` is configured to disable SSL verification, False otherwise.
        """
        if "git config" not in command_string:
            return False

        # Check for git config commands that disable SSL verification
        match = re.search(r"git\s+config\s+.*http\.sslVerify\s+false", command_string)

        return bool(match)


@pytest.fixture
def git_ssl_verification_disabled():
    return SEC0025()


def test_git_ssl_verification_disabled_detects_disabled_verification(git_ssl_verification_disabled):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "git config --global http.sslVerify false"},
    ]
    errors = git_ssl_verification_disabled.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "`git` is configured to disable SSL verification" in errors[0]["message"]


def test_git_ssl_verification_disabled_allows_enabled_verification(git_ssl_verification_disabled):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "git config --global http.sslVerify true"},
    ]
    errors = git_ssl_verification_disabled.check(parsed_content)
    assert len(errors) == 0


def test_git_ssl_verification_disabled_ignores_other_commands(git_ssl_verification_disabled):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "echo hello"},
    ]
    errors = git_ssl_verification_disabled.check(parsed_content)
    assert len(errors) == 0


def test_git_ssl_verification_disabled_ignores_other_instructions(git_ssl_verification_disabled):
    parsed_content = [
        {"line": 1, "instruction": "ENV", "arguments": "MY_VAR=value"},
    ]
    errors = git_ssl_verification_disabled.check(parsed_content)
    assert len(errors) == 0
