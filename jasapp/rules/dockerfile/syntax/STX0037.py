import re
import pytest
from jasapp.rules.base_rule import BaseRule


class STX0037(BaseRule):
    """
    Rule to ensure `dnf clean all` or `rm -rf /var/cache/yum/*` is present after `dnf install` commands in RUN instructions.
    """
    rule_type = "dockerfile"

    def __init__(self):
        super().__init__(
            friendly_name="DnfCleanAllAfterInstall",
            hadolint="DL3040",
            name="STX0037",
            description="`dnf clean all` or `rm -rf /var/cache/yum/*` should be present after `dnf install` commands.",
            severity="warning",
        )

    def check(self, instructions):
        """
        Checks if `dnf clean all` or `rm -rf /var/cache/yum/*` is present after `dnf install` commands in RUN instructions.

        Args:
            instructions (list): A list of dictionaries containing parsed Dockerfile instructions.

        Returns:
            list: A list of errors found, each as a dictionary with line, message, and severity.
        """
        errors = []

        for instr in instructions:
            if instr["instruction"] == "RUN":
                commands = self.split_commands(instr["arguments"])
                if self.has_dnf_install_without_clean(commands):
                    errors.append({
                        "line": instr["line"],
                        "message": "`dnf clean all` or `rm -rf /var/cache/yum/*` missing after `dnf install` command.",
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

    def has_dnf_install_without_clean(self, commands):
        """
        Checks if a list of commands has a `dnf install` command without a corresponding `dnf clean all`
        or `rm -rf /var/cache/yum/*` command.

        Args:
            commands (list): A list of command strings.

        Returns:
            bool: True if a `dnf install` without a corresponding clean is found, False otherwise.
        """
        has_install = False
        has_clean = False

        for command in commands:
            if self.is_dnf_install(command):
                has_install = True
            elif self.is_dnf_clean(command):
                has_clean = True

        return has_install and not has_clean

    def is_dnf_install(self, command_string):
        """
        Checks if a command string is a `dnf install` command.

        Args:
            command_string (str): The command string to check.

        Returns:
            bool: True if it's a `dnf install` command, False otherwise.
        """
        return ("dnf" in command_string or "microdnf" in command_string) and "install" in command_string

    def is_dnf_clean(self, command_string):
        """
        Checks if a command string is a `dnf clean all` or `rm -rf /var/cache/yum/*` command.

        Args:
            command_string (str): The command string to check.

        Returns:
            bool: True if it's a `dnf clean` command, False otherwise.
        """
        return (
            ("dnf" in command_string or "microdnf" in command_string) and "clean all" in command_string
            or "rm -rf /var/cache/yum" in command_string
        )


@pytest.fixture
def dnf_clean_all_after_install():
    return STX0037()


def test_dnf_clean_all_detects_missing_clean(dnf_clean_all_after_install):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "dnf install -y httpd"},
    ]
    errors = dnf_clean_all_after_install.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "`dnf clean all` or `rm -rf /var/cache/yum/*` missing" in errors[0]["message"]


def test_dnf_clean_all_allows_dnf_clean_all(dnf_clean_all_after_install):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "dnf install -y httpd && dnf clean all"},
    ]
    errors = dnf_clean_all_after_install.check(parsed_content)
    assert len(errors) == 0


def test_dnf_clean_all_allows_rm_rf_var_cache_yum(dnf_clean_all_after_install):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "dnf install -y httpd && rm -rf /var/cache/yum/*"},
    ]
    errors = dnf_clean_all_after_install.check(parsed_content)
    assert len(errors) == 0


def test_dnf_clean_all_allows_microdnf_clean_all(dnf_clean_all_after_install):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "microdnf install -y httpd && microdnf clean all"},
    ]
    errors = dnf_clean_all_after_install.check(parsed_content)
    assert len(errors) == 0


def test_dnf_clean_all_ignores_other_commands(dnf_clean_all_after_install):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "echo hello"},
    ]
    errors = dnf_clean_all_after_install.check(parsed_content)
    assert len(errors) == 0


def test_dnf_clean_all_handles_complex_commands(dnf_clean_all_after_install):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "dnf install -y httpd && dnf update && dnf clean all"},
    ]
    errors = dnf_clean_all_after_install.check(parsed_content)
    assert len(errors) == 0


def test_dnf_clean_all_handles_complex_commands_missing_clean(dnf_clean_all_after_install):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "dnf install -y httpd && dnf update"},
    ]
    errors = dnf_clean_all_after_install.check(parsed_content)
    assert len(errors) == 1
    assert "`dnf clean all` or `rm -rf /var/cache/yum/*` missing" in errors[0]["message"]


def test_dnf_clean_all_handles_complex_commands_with_semicolon(dnf_clean_all_after_install):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "dnf install -y httpd; dnf update; dnf clean all"},
    ]
    errors = dnf_clean_all_after_install.check(parsed_content)
    assert len(errors) == 0


def test_dnf_clean_all_handles_complex_commands_with_semicolon_missing_clean(dnf_clean_all_after_install):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "dnf install -y httpd; dnf update"},
    ]
    errors = dnf_clean_all_after_install.check(parsed_content)
    assert len(errors) == 1
    assert "`dnf clean all` or `rm -rf /var/cache/yum/*` missing" in errors[0]["message"]
