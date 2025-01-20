import re
import pytest
from jasapp.rules.base_rule import BaseRule


class SEC0004(BaseRule):
    """
    Rule to ensure that package manager update commands are not used alone in a single RUN instruction.
    """
    rule_type = "dockerfile"

    def __init__(self):
        super().__init__(
            friendly_name="UpdateAlone",
            hadolint="CISDI0007",
            name="SEC0004",
            description="Do not use `update` instructions alone in the Dockerfile.",
            severity="info",
        )

    def check(self, instructions):
        """
        Checks if package manager update commands are used alone in a single RUN instruction.

        Args:
            instructions (list): A list of dictionaries containing parsed Dockerfile instructions.

        Returns:
            list: A list of errors found, each as a dictionary with line, message, and severity.
        """
        errors = []

        for instr in instructions:
            if instr["instruction"] == "RUN":
                if self.is_update_alone(instr["arguments"]):
                    errors.append({
                        "line": instr["line"],
                        "message": "Do not use `update` instructions alone in the Dockerfile. "
                                   "Combine `update` with `install` in a single `RUN` instruction to avoid caching issues.",
                        "severity": self.severity,
                        "doc_link": f"https://github.com/jassouline/jasapp/wiki/{self.name}"
                    })

        return errors

    def is_update_alone(self, command_string):
        """
        Checks if a command string contains only a package manager update command.

        Args:
            command_string (str): The command string to check.

        Returns:
            bool: True if the command string contains only an update command, False otherwise.
        """
        # List of common package manager update commands
        update_commands = [
            "apt-get update",
            "yum update",
            "apk update",
            "pacman -Syu",
            "zypper update",
            "yum upgrade",  # yum also uses 'upgrade' for updates
            "dnf update",
            "dnf upgrade",
        ]

        command_string = command_string.strip()

        # Check if the command string matches any of the update commands, ignoring other options or arguments
        for update_command in update_commands:
            pattern = rf"^{re.escape(update_command)}(\s+[\-a-zA-Z0-9]+)*$"
            if re.match(pattern, command_string):
                return True

        return False


@pytest.fixture
def update_alone():
    return SEC0004()


def test_update_alone_detects_apt_get_update_alone(update_alone):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "apt-get update"},
    ]
    errors = update_alone.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "Do not use `update` instructions alone" in errors[0]["message"]


def test_update_alone_detects_yum_update_alone(update_alone):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "yum update"},
    ]
    errors = update_alone.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "Do not use `update` instructions alone" in errors[0]["message"]


def test_update_alone_allows_update_with_install(update_alone):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "apt-get update && apt-get install -y curl"},
    ]
    errors = update_alone.check(parsed_content)
    assert len(errors) == 0


def test_update_alone_ignores_other_instructions(update_alone):
    parsed_content = [
        {"line": 1, "instruction": "ENV", "arguments": "MY_VAR=value"},
    ]
    errors = update_alone.check(parsed_content)
    assert len(errors) == 0


def test_update_alone_handles_complex_commands(update_alone):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "apt-get update && apt-get install -y curl && dnf update"},
    ]
    errors = update_alone.check(parsed_content)
    assert len(errors) == 0


def test_update_alone_handles_complex_commands_with_semicolon(update_alone):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "apt-get update; apt-get install -y curl; dnf update"},
    ]
    errors = update_alone.check(parsed_content)
    assert len(errors) == 0


def test_update_alone_detects_yum_update_alone_with_options(update_alone):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "yum update -y"},
    ]
    errors = update_alone.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "Do not use `update` instructions alone" in errors[0]["message"]
