import pytest
from jasapp.rules.base_rule import BaseRule


class SEC0018(BaseRule):
    """
    Rule to detect if the `apk` package manager is configured to allow untrusted repositories.
    """
    rule_type = "dockerfile"

    def __init__(self):
        super().__init__(
            friendly_name="ApkAllowUntrusted",
            name="SEC0018",
            description="`apk` is configured to allow untrusted repositories.",
            severity="error",
        )

    def check(self, instructions):
        """
        Checks if `apk` commands in `RUN` instructions allow untrusted repositories.

        Args:
            instructions (list): A list of dictionaries containing parsed Dockerfile instructions.

        Returns:
            list: A list of errors found, each as a dictionary with line, message, and severity.
        """
        errors = []

        for instr in instructions:
            if instr["instruction"] == "RUN":
                if self.is_apk_allowing_untrusted(instr["arguments"]):
                    errors.append({
                        "line": instr["line"],
                        "message": "`apk` is configured to allow untrusted repositories. "
                                   "Use `--allow-untrusted` or `--no-allow-untrusted` explicitly.",
                        "severity": self.severity,
                        "doc_link": f"https://github.com/jassouline/jasapp/wiki/{self.name}"
                    })

        return errors

    def is_apk_allowing_untrusted(self, command_string):
        """
        Checks if a command string contains an `apk` command that allows untrusted repositories.

        Args:
            command_string (str): The command string to check.

        Returns:
            bool: True if `apk` allows untrusted repositories, False otherwise.
        """
        if "apk" not in command_string:
            return False

        # Check for the absence of --no-allow-untrusted and presence of --allow-untrusted
        return "--allow-untrusted" in command_string and "--no-allow-untrusted" not in command_string


@pytest.fixture
def apk_untrusted_repositories():
    return SEC0018()


def test_apk_untrusted_detects_allow_untrusted(apk_untrusted_repositories):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "apk add --allow-untrusted curl"},
    ]
    errors = apk_untrusted_repositories.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "`apk` is configured to allow untrusted repositories" in errors[0]["message"]


def test_apk_untrusted_allows_no_allow_untrusted(apk_untrusted_repositories):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "apk add --no-allow-untrusted curl"},
    ]
    errors = apk_untrusted_repositories.check(parsed_content)
    assert len(errors) == 0


def test_apk_untrusted_allows_secure_apk(apk_untrusted_repositories):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "apk add curl"},
    ]
    errors = apk_untrusted_repositories.check(parsed_content)
    assert len(errors) == 0


def test_apk_untrusted_ignores_other_instructions(apk_untrusted_repositories):
    parsed_content = [
        {"line": 1, "instruction": "ENV", "arguments": "MY_VAR=value"},
    ]
    errors = apk_untrusted_repositories.check(parsed_content)
    assert len(errors) == 0
