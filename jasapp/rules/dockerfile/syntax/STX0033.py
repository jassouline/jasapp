import re
import pytest
from jasapp.rules.base_rule import BaseRule


class STX0033(BaseRule):
    """
    Rule to ensure `zypper dist-upgrade` or `zypper dup` are not used in RUN instructions.
    """
    rule_type = "dockerfile"

    def __init__(self):
        super().__init__(
            friendly_name="DoNotUseZypperDistUpgrade",
            hadolint="DL3035",
            name="STX0033",
            description="Do not use `zypper dist-upgrade` or `zypper dup`.",
            severity="warning",
        )

    def check(self, instructions):
        """
        Checks if `zypper dist-upgrade` or `zypper dup` are used in RUN instructions.

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
                    if self.is_zypper_dist_upgrade(command):
                        errors.append({
                            "line": instr["line"],
                            "message": "Do not use `zypper dist-upgrade` or `zypper dup`.",
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

    def is_zypper_dist_upgrade(self, command_string):
        """
        Checks if a command string is a `zypper dist-upgrade` or `zypper dup` command.

        Args:
            command_string (str): The command string to check.

        Returns:
            bool: True if it's a `zypper dist-upgrade` or `zypper dup` command, False otherwise.
        """
        if "zypper" not in command_string:
            return False

        words = re.split(r"\s+", command_string)
        return ("dist-upgrade" in words or "dup" in words)


@pytest.fixture
def do_not_use_zypper_dist_upgrade():
    return STX0033()


def test_zypper_dist_upgrade_detects_dist_upgrade(do_not_use_zypper_dist_upgrade):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "zypper dist-upgrade"},
    ]
    errors = do_not_use_zypper_dist_upgrade.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "Do not use `zypper dist-upgrade` or `zypper dup`" in errors[0]["message"]


def test_zypper_dist_upgrade_detects_dup(do_not_use_zypper_dist_upgrade):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "zypper dup"},
    ]
    errors = do_not_use_zypper_dist_upgrade.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "Do not use `zypper dist-upgrade` or `zypper dup`" in errors[0]["message"]


def test_zypper_dist_upgrade_allows_other_zypper_commands(do_not_use_zypper_dist_upgrade):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "zypper install -y httpd"},
    ]
    errors = do_not_use_zypper_dist_upgrade.check(parsed_content)
    assert len(errors) == 0


def test_zypper_dist_upgrade_ignores_other_instructions(do_not_use_zypper_dist_upgrade):
    parsed_content = [
        {"line": 1, "instruction": "ENV", "arguments": "MY_VAR=value"},
    ]
    errors = do_not_use_zypper_dist_upgrade.check(parsed_content)
    assert len(errors) == 0


def test_zypper_dist_upgrade_handles_complex_commands(do_not_use_zypper_dist_upgrade):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "zypper install -y httpd && zypper dup"},
    ]
    errors = do_not_use_zypper_dist_upgrade.check(parsed_content)
    assert len(errors) == 1
    assert "zypper dup" in errors[0]["message"]


def test_zypper_dist_upgrade_handles_complex_commands_with_semicolon(do_not_use_zypper_dist_upgrade):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "zypper install -y httpd; zypper dist-upgrade"},
    ]
    errors = do_not_use_zypper_dist_upgrade.check(parsed_content)
    assert len(errors) == 1
    assert "zypper dist-upgrade" in errors[0]["message"]
