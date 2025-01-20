import re
import pytest
from jasapp.rules.base_rule import BaseRule


class STX0029(BaseRule):
    """
    Rule to ensure `yum install` in RUN instructions uses the `-y` flag.
    """
    rule_type = "dockerfile"

    def __init__(self):
        super().__init__(
            friendly_name="UseYumInstallWithYFlag",
            hadolint="DL3030",
            name="STX0029",
            description="Use the -y switch to avoid manual input `yum install -y <package>`",
            severity="warning",
        )

    def check(self, instructions):
        """
        Checks if `yum install` in RUN instructions uses the `-y` flag.

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
                    if self.is_yum_install_without_y(command):
                        errors.append({
                            "line": instr["line"],
                            "message": "Use the -y switch to avoid manual input `yum install -y <package>`",
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

    def is_yum_install_without_y(self, command_string):
        """
        Checks if a command string is a `yum install` command without the `-y` flag.

        Args:
            command_string (str): The command string to check.

        Returns:
            bool: True if it's a `yum install` without `-y`, False otherwise.
        """
        if "yum" not in command_string:
            return False

        words = re.split(r"\s+", command_string)

        if "install" not in words and "localinstall" not in words and "groupinstall" not in words:
            return False

        if "-y" in words or "--assumeyes" in words:
            return False

        return True


@pytest.fixture
def use_yum_install_with_y_flag():
    return STX0029()


def test_use_yum_install_with_y_detects_missing_y(use_yum_install_with_y_flag):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "yum install httpd"},
    ]
    errors = use_yum_install_with_y_flag.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "Use the -y switch" in errors[0]["message"]


def test_use_yum_install_with_y_allows_y_flag(use_yum_install_with_y_flag):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "yum install -y httpd"},
    ]
    errors = use_yum_install_with_y_flag.check(parsed_content)
    assert len(errors) == 0


def test_use_yum_install_with_y_allows_assumeyes_flag(use_yum_install_with_y_flag):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "yum install --assumeyes httpd"},
    ]
    errors = use_yum_install_with_y_flag.check(parsed_content)
    assert len(errors) == 0


def test_use_yum_install_with_y_ignores_other_yum_commands(use_yum_install_with_y_flag):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "yum update"},
    ]
    errors = use_yum_install_with_y_flag.check(parsed_content)
    assert len(errors) == 0


def test_use_yum_install_with_y_ignores_other_instructions(use_yum_install_with_y_flag):
    parsed_content = [
        {"line": 1, "instruction": "ENV", "arguments": "MY_VAR=value"},
    ]
    errors = use_yum_install_with_y_flag.check(parsed_content)
    assert len(errors) == 0


def test_use_yum_install_with_y_handles_complex_commands(use_yum_install_with_y_flag):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "yum install httpd && yum install -y mysql"},
    ]
    errors = use_yum_install_with_y_flag.check(parsed_content)
    assert len(errors) == 1
    assert "Use the -y switch" in errors[0]["message"]


def test_use_yum_install_with_y_handles_complex_commands_with_semicolon(use_yum_install_with_y_flag):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "yum install httpd; yum install -y mysql"},
    ]
    errors = use_yum_install_with_y_flag.check(parsed_content)
    assert len(errors) == 1
    assert "Use the -y switch" in errors[0]["message"]
