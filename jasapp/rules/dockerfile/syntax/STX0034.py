import re
import pytest
from jasapp.rules.base_rule import BaseRule


class STX0034(BaseRule):
    """
    Rule to ensure `zypper clean` is present after `zypper install` or `zypper in` commands in RUN instructions.
    """
    rule_type = "dockerfile"

    def __init__(self):
        super().__init__(
            friendly_name="ZypperCleanAfterUse",
            hadolint="DL3036",
            name="STX0034",
            description="`zypper clean` should be present after `zypper install` or `zypper in` commands.",
            severity="warning",
        )

    def check(self, instructions):
        """
        Checks if `zypper clean` is present after `zypper install` or `zypper in` commands in RUN instructions.

        Args:
            instructions (list): A list of dictionaries containing parsed Dockerfile instructions.

        Returns:
            list: A list of errors found, each as a dictionary with line, message, and severity.
        """
        errors = []

        for instr in instructions:
            if instr["instruction"] == "RUN":
                commands = self.split_commands(instr["arguments"])
                if self.has_zypper_install_without_clean(commands):
                    errors.append({
                        "line": instr["line"],
                        "message": "`zypper clean` missing after `zypper install` or `zypper in` command.",
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

    def has_zypper_install_without_clean(self, commands):
        """
        Checks if a list of commands has a `zypper install` or `zypper in` command without a corresponding `zypper clean`
        or `zypper cc` command.

        Args:
            commands (list): A list of command strings.

        Returns:
            bool: True if a `zypper install` or `zypper in` without a corresponding clean is found, False otherwise.
        """
        has_install = False
        has_clean = False

        for command in commands:
            if self.is_zypper_install(command):
                has_install = True
            elif self.is_zypper_clean(command):
                has_clean = True

        return has_install and not has_clean

    def is_zypper_install(self, command_string):
        """
        Checks if a command string is a `zypper install` or `zypper in` command.

        Args:
            command_string (str): The command string to check.

        Returns:
            bool: True if it's a `zypper install` or `zypper in` command, False otherwise.
        """
        return "zypper" in command_string and ("install" in command_string or "in" in command_string)

    def is_zypper_clean(self, command_string):
        """
        Checks if a command string is a `zypper clean` or `zypper cc` command.

        Args:
            command_string (str): The command string to check.

        Returns:
            bool: True if it's a `zypper clean` or `zypper cc` command, False otherwise.
        """
        return ("zypper" in command_string and "clean" in command_string) or \
               ("zypper" in command_string and "cc" in command_string)


@pytest.fixture
def zypper_clean_after_use():
    return STX0034()


def test_zypper_clean_detects_missing_clean(zypper_clean_after_use):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "zypper install -y httpd"},
    ]
    errors = zypper_clean_after_use.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "`zypper clean` missing after `zypper install` or `zypper in` command" in errors[0]["message"]


def test_zypper_clean_allows_zypper_clean(zypper_clean_after_use):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "zypper install -y httpd && zypper clean"},
    ]
    errors = zypper_clean_after_use.check(parsed_content)
    assert len(errors) == 0


def test_zypper_clean_allows_zypper_cc(zypper_clean_after_use):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "zypper install -y httpd && zypper cc"},
    ]
    errors = zypper_clean_after_use.check(parsed_content)
    assert len(errors) == 0


def test_zypper_clean_ignores_other_commands(zypper_clean_after_use):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "echo hello"},
    ]
    errors = zypper_clean_after_use.check(parsed_content)
    assert len(errors) == 0


def test_zypper_clean_handles_complex_commands(zypper_clean_after_use):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "zypper install -y httpd && zypper update && zypper clean"},
    ]
    errors = zypper_clean_after_use.check(parsed_content)
    assert len(errors) == 0


def test_zypper_clean_handles_complex_commands_missing_clean(zypper_clean_after_use):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "zypper install -y httpd && zypper update"},
    ]
    errors = zypper_clean_after_use.check(parsed_content)
    assert len(errors) == 1
    assert "`zypper clean` missing" in errors[0]["message"]


def test_zypper_clean_handles_complex_commands_with_semicolon(zypper_clean_after_use):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "zypper install -y httpd; zypper update; zypper clean"},
    ]
    errors = zypper_clean_after_use.check(parsed_content)
    assert len(errors) == 0


def test_zypper_clean_handles_complex_commands_with_semicolon_missing_clean(zypper_clean_after_use):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "zypper in -y httpd; zypper update"},
    ]
    errors = zypper_clean_after_use.check(parsed_content)
    assert len(errors) == 1
    assert "`zypper clean` missing" in errors[0]["message"]
