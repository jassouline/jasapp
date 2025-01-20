import re
import pytest
from jasapp.rules.base_rule import BaseRule


class STX0032(BaseRule):
    """
    Rule to ensure `zypper` commands in RUN instructions use the `--non-interactive` flag.
    """
    rule_type = "dockerfile"

    def __init__(self):
        super().__init__(
            friendly_name="UseZypperNonInteractive",
            hadolint="DL3034",
            name="STX0032",
            description="Non-interactive switch missing from `zypper` command: `zypper --non-interactive install <package>`",
            severity="warning",
        )

    def check(self, instructions):
        """
        Checks if `zypper` commands in RUN instructions use the `--non-interactive` flag.

        Args:
            instructions (list): A list of dictionaries containing parsed Dockerfile instructions.

        Returns:
            list: A list of errors found, each as a dictionary with line, message, and severity.
        """
        errors = []

        for instr in instructions:
            if instr["instruction"] == "RUN":
                commands = self.split_commands(instr["arguments"])
                for command in commands:
                    if self.is_zypper_command_without_non_interactive(command):
                        errors.append({
                            "line": instr["line"],
                            "message": "Non-interactive switch missing from `zypper` command",
                            "severity": self.severity,
                            "doc_link": f"https://github.com/jassouline/jasapp/wiki/{self.name}"
                        })

        return errors

    def split_commands(self, command_string):
        """
        Splits a command string into multiple commands based on && and ; delimiters.

        Args:
            command_string (str): The command string to split.

        Returns:
            list: A list of individual commands.
        """
        commands = re.split(r"[;&]", command_string)
        return [command.strip() for command in commands if command.strip()]

    def is_zypper_command_without_non_interactive(self, command_string):
        """
        Checks if a command string is a `zypper` command that modifies the system without the `--non-interactive` flag.

        Args:
            command_string (str): The command string to check.

        Returns:
            bool: True if it's a `zypper` command without `--non-interactive`, False otherwise.
        """
        if "zypper" not in command_string:
            return False

        words = re.split(r"\s+", command_string)
        if not any(
            word in ["install", "in", "remove", "rm", "source-install", "si", "patch"]
            for word in words
        ):
            return False

        if any(
            word in ["--non-interactive", "-n", "--no-confirm", "-y"] for word in words
        ):
            return False

        return True


@pytest.fixture
def use_zypper_non_interactive():
    return STX0032()


def test_zypper_non_interactive_detects_missing_flag(use_zypper_non_interactive):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "zypper install httpd"},
    ]
    errors = use_zypper_non_interactive.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "Non-interactive switch missing from `zypper` command" in errors[0]["message"]


def test_zypper_non_interactive_allows_non_interactive_flag(use_zypper_non_interactive):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "zypper --non-interactive install httpd"},
    ]
    errors = use_zypper_non_interactive.check(parsed_content)
    assert len(errors) == 0


def test_zypper_non_interactive_allows_short_flags(use_zypper_non_interactive):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "zypper -n install httpd"},
    ]
    errors = use_zypper_non_interactive.check(parsed_content)
    assert len(errors) == 0

    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "zypper -y install httpd"},
    ]
    errors = use_zypper_non_interactive.check(parsed_content)
    assert len(errors) == 0


def test_zypper_non_interactive_ignores_other_commands(use_zypper_non_interactive):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "echo hello"},
    ]
    errors = use_zypper_non_interactive.check(parsed_content)
    assert len(errors) == 0


def test_zypper_non_interactive_ignores_other_zypper_commands(use_zypper_non_interactive):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "zypper update"},
    ]
    errors = use_zypper_non_interactive.check(parsed_content)
    assert len(errors) == 0


def test_zypper_non_interactive_handles_complex_commands(use_zypper_non_interactive):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "zypper install httpd && zypper --non-interactive install mysql"},
    ]
    errors = use_zypper_non_interactive.check(parsed_content)
    assert len(errors) == 1
    assert "Non-interactive switch missing from `zypper` command" in errors[0]["message"]


def test_zypper_non_interactive_handles_complex_commands_with_semicolon(use_zypper_non_interactive):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "zypper install httpd; zypper -n install mysql"},
    ]
    errors = use_zypper_non_interactive.check(parsed_content)
    assert len(errors) == 1
    assert "Non-interactive switch missing from `zypper` command" in errors[0]["message"]
