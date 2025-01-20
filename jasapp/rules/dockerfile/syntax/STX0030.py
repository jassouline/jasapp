import re
import pytest
from jasapp.rules.base_rule import BaseRule


class STX0030(BaseRule):
    """
    Rule to ensure `yum clean all` is present after `yum install` commands in RUN instructions.
    """
    rule_type = "dockerfile"

    def __init__(self):
        super().__init__(
            friendly_name="YumCleanAllAfterInstall",
            hadolint="DL3032",
            name="STX0030",
            description="`yum clean all` should be present after `yum install` commands.",
            severity="warning",
        )

    def check(self, instructions):
        """
        Checks if `yum clean all` is present after `yum install` commands in RUN instructions.

        Args:
            instructions (list): A list of dictionaries containing parsed Dockerfile instructions.

        Returns:
            list: A list of errors found, each as a dictionary with line, message, and severity.
        """
        errors = []

        for instr in instructions:
            if instr["instruction"] == "RUN":
                commands = self.split_commands(instr["arguments"])
                if self.has_yum_install_without_clean(commands):
                    errors.append({
                        "line": instr["line"],
                        "message": "`yum clean all` missing after `yum install` command.",
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

    def has_yum_install_without_clean(self, commands):
        """
        Checks if a list of commands has a `yum install` command without a corresponding `yum clean all`
        or `rm -rf /var/cache/yum/*` command.

        Args:
            commands (list): A list of command strings.

        Returns:
            bool: True if a `yum install` without a corresponding clean is found, False otherwise.
        """
        has_install = False
        has_clean = False

        for command in commands:
            if self.is_yum_install(command):
                has_install = True
            elif self.is_yum_clean(command):
                has_clean = True

        return has_install and not has_clean

    def is_yum_install(self, command_string):
        """
        Checks if a command string is a `yum install` command.

        Args:
            command_string (str): The command string to check.

        Returns:
            bool: True if it's a `yum install` command, False otherwise.
        """
        return "yum" in command_string and "install" in command_string

    def is_yum_clean(self, command_string):
        """
        Checks if a command string is a `yum clean all` or `rm -rf /var/cache/yum/*` command.

        Args:
            command_string (str): The command string to check.

        Returns:
            bool: True if it's a `yum clean` command, False otherwise.
        """
        return ("yum" in command_string and "clean all" in command_string) or \
               ("rm" in command_string and "-rf /var/cache/yum" in command_string)


@pytest.fixture
def yum_clean_all_after_install():
    return STX0030()


def test_yum_clean_all_detects_missing_clean(yum_clean_all_after_install):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "yum install -y httpd"},
    ]
    errors = yum_clean_all_after_install.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "yum clean all" in errors[0]["message"]


def test_yum_clean_all_allows_yum_clean_all(yum_clean_all_after_install):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "yum install -y httpd && yum clean all"},
    ]
    errors = yum_clean_all_after_install.check(parsed_content)
    assert len(errors) == 0


def test_yum_clean_all_allows_rm_rf_var_cache_yum(yum_clean_all_after_install):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "yum install -y httpd && rm -rf /var/cache/yum/*"},
    ]
    errors = yum_clean_all_after_install.check(parsed_content)
    assert len(errors) == 0


def test_yum_clean_all_ignores_other_commands(yum_clean_all_after_install):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "echo hello"},
    ]
    errors = yum_clean_all_after_install.check(parsed_content)
    assert len(errors) == 0


def test_yum_clean_all_handles_complex_commands(yum_clean_all_after_install):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "yum install -y httpd && yum update && yum clean all"},
    ]
    errors = yum_clean_all_after_install.check(parsed_content)
    assert len(errors) == 0


def test_yum_clean_all_handles_complex_commands_missing_clean(yum_clean_all_after_install):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "yum install -y httpd && yum update"},
    ]
    errors = yum_clean_all_after_install.check(parsed_content)
    assert len(errors) == 1
    assert "yum clean all" in errors[0]["message"]


def test_yum_clean_all_handles_complex_commands_with_semicolon(yum_clean_all_after_install):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "yum install -y httpd; yum update; yum clean all"},
    ]
    errors = yum_clean_all_after_install.check(parsed_content)
    assert len(errors) == 0


def test_yum_clean_all_handles_complex_commands_with_semicolon_missing_clean(yum_clean_all_after_install):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "yum install -y httpd; yum update"},
    ]
    errors = yum_clean_all_after_install.check(parsed_content)
    assert len(errors) == 1
    assert "yum clean all" in errors[0]["message"]
