import re
import pytest
from jasapp.rules.base_rule import BaseRule


class STX0036(BaseRule):
    """
    Rule to ensure `dnf install`, `dnf groupinstall`, or `dnf localinstall` in RUN instructions uses the `-y` flag.
    """
    rule_type = "dockerfile"

    def __init__(self):
        super().__init__(
            friendly_name="UseDnfInstallWithYFlag",
            hadolint="DL3038",
            name="STX0036",
            description="Use the -y switch to avoid manual input `dnf install -y <package>`",
            severity="warning",
        )

    def check(self, instructions):
        """
        Checks if `dnf install`, `dnf groupinstall`, or `dnf localinstall` in RUN instructions uses the `-y` flag.

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
                    if self.is_dnf_install_without_y(command):
                        errors.append({
                            "line": instr["line"],
                            "message": "Use the -y switch to avoid manual input `dnf install -y <package>`",
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

    def is_dnf_install_without_y(self, command_string):
        """
        Checks if a command string is a `dnf install`, `dnf groupinstall`, or `dnf localinstall` command
        without the `-y` flag.

        Args:
            command_string (str): The command string to check.

        Returns:
            bool: True if it's a `dnf install/groupinstall/localinstall` without `-y`, False otherwise.
        """
        if not any(cmd in command_string for cmd in ["dnf", "microdnf"]):
            return False

        words = re.split(r"\s+", command_string)
        if not any(
            word in ["install", "groupinstall", "localinstall"]
            for word in words
        ):
            return False

        if "-y" in words or "--assumeyes" in words:
            return False

        return True


@pytest.fixture
def use_dnf_install_with_y_flag():
    return STX0036()


def test_dnf_install_with_y_detects_missing_y(use_dnf_install_with_y_flag):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "dnf install httpd"},
    ]
    errors = use_dnf_install_with_y_flag.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "Use the -y switch to avoid manual input `dnf install -y <package>`" in errors[0]["message"]


def test_dnf_install_with_y_allows_y_flag(use_dnf_install_with_y_flag):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "dnf install -y httpd"},
    ]
    errors = use_dnf_install_with_y_flag.check(parsed_content)
    assert len(errors) == 0


def test_dnf_install_with_y_allows_assumeyes_flag(use_dnf_install_with_y_flag):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "dnf install --assumeyes httpd"},
    ]
    errors = use_dnf_install_with_y_flag.check(parsed_content)
    assert len(errors) == 0


def test_dnf_install_with_y_ignores_other_dnf_commands(use_dnf_install_with_y_flag):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "dnf update"},
    ]
    errors = use_dnf_install_with_y_flag.check(parsed_content)
    assert len(errors) == 0


def test_dnf_install_with_y_ignores_other_instructions(use_dnf_install_with_y_flag):
    parsed_content = [
        {"line": 1, "instruction": "ENV", "arguments": "MY_VAR=value"},
    ]
    errors = use_dnf_install_with_y_flag.check(parsed_content)
    assert len(errors) == 0


def test_dnf_install_with_y_handles_complex_commands(use_dnf_install_with_y_flag):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "dnf install httpd && dnf install -y mysql"},
    ]
    errors = use_dnf_install_with_y_flag.check(parsed_content)
    assert len(errors) == 1
    assert "Use the -y switch to avoid manual input `dnf install -y <package>`" in errors[0]["message"]


def test_dnf_install_with_y_handles_complex_commands_with_semicolon(use_dnf_install_with_y_flag):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "dnf install httpd; dnf install -y mysql"},
    ]
    errors = use_dnf_install_with_y_flag.check(parsed_content)
    assert len(errors) == 1
    assert "Use the -y switch to avoid manual input `dnf install -y <package>`" in errors[0]["message"]


def test_dnf_install_with_y_handles_microdnf(use_dnf_install_with_y_flag):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "microdnf install -y httpd"},
    ]
    errors = use_dnf_install_with_y_flag.check(parsed_content)
    assert len(errors) == 0


def test_dnf_install_with_y_detects_missing_y_with_microdnf(use_dnf_install_with_y_flag):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "microdnf install httpd"},
    ]
    errors = use_dnf_install_with_y_flag.check(parsed_content)
    assert len(errors) == 1
    assert "Use the -y switch to avoid manual input `dnf install -y <package>`" in errors[0]["message"]
