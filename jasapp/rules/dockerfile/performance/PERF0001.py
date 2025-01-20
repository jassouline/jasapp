import re
import pytest
from jasapp.rules.base_rule import BaseRule


class PERF0001(BaseRule):
    """
    Rule to ensure `useradd` in RUN instructions uses the `-l` flag or avoids high UIDs to prevent large image sizes.
    """
    rule_type = "dockerfile"

    def __init__(self):
        super().__init__(
            friendly_name="UseUseraddWithLFlagOrLowUid",
            hadolint="DL3046",
            name="PERF0001",
            description="`useradd` without flag `-l` and high UID will result in excessively large image.",
            severity="warning",
        )

    def check(self, instructions):
        """
        Checks if `useradd` in RUN instructions uses the `-l` flag or avoids high UIDs.

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
                    if self.is_useradd_without_l_and_high_uid(command):
                        errors.append({
                            "line": instr["line"],
                            "message": "`useradd` without flag `-l` and high UID will result in excessively large image.",
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

    def is_useradd_without_l_and_high_uid(self, command_string):
        """
        Checks if a command string is a `useradd` command without the `-l` flag and with a high UID.

        Args:
            command_string (str): The command string to check.

        Returns:
            bool: True if it's a `useradd` without `-l` and with a high UID, False otherwise.
        """
        if "useradd" not in command_string:
            return False

        words = re.split(r"\s+", command_string)
        if "-l" in words or "--no-log-init" in words:
            return False

        uid_index = None
        for i, word in enumerate(words):
            if word in ["-u", "--uid"]:
                uid_index = i + 1
                break

        if uid_index is None or uid_index >= len(words):
            return False

        uid_value = words[uid_index]
        try:
            return len(uid_value) > 5  # UID is considered high if it has more than 5 digits
        except ValueError:
            return False


@pytest.fixture
def use_useradd_with_l_flag_or_low_uid():
    return PERF0001()


def test_useradd_without_l_detects_high_uid(use_useradd_with_l_flag_or_low_uid):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "useradd -u 100000 testuser"},
    ]
    errors = use_useradd_with_l_flag_or_low_uid.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "`useradd` without flag `-l` and high UID" in errors[0]["message"]


def test_useradd_without_l_allows_low_uid(use_useradd_with_l_flag_or_low_uid):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "useradd -u 1000 testuser"},
    ]
    errors = use_useradd_with_l_flag_or_low_uid.check(parsed_content)
    assert len(errors) == 0


def test_useradd_with_l_allows_high_uid(use_useradd_with_l_flag_or_low_uid):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "useradd -l -u 100000 testuser"},
    ]
    errors = use_useradd_with_l_flag_or_low_uid.check(parsed_content)
    assert len(errors) == 0


def test_useradd_with_long_option_allows_high_uid(use_useradd_with_l_flag_or_low_uid):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "useradd --no-log-init -u 100000 testuser"},
    ]
    errors = use_useradd_with_l_flag_or_low_uid.check(parsed_content)
    assert len(errors) == 0


def test_useradd_without_l_ignores_other_commands(use_useradd_with_l_flag_or_low_uid):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "echo hello"},
    ]
    errors = use_useradd_with_l_flag_or_low_uid.check(parsed_content)
    assert len(errors) == 0


def test_useradd_without_l_handles_complex_commands(use_useradd_with_l_flag_or_low_uid):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "useradd -u 1000 testuser && useradd -u 999999 baduser"},
    ]
    errors = use_useradd_with_l_flag_or_low_uid.check(parsed_content)
    assert len(errors) == 1
    assert "`useradd` without flag `-l` and high UID" in errors[0]["message"]


def test_useradd_without_l_handles_complex_commands_with_semicolon(use_useradd_with_l_flag_or_low_uid):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "useradd -u 1000 testuser; useradd -u 999999 baduser"},
    ]
    errors = use_useradd_with_l_flag_or_low_uid.check(parsed_content)
    assert len(errors) == 1
    assert "`useradd` without flag `-l` and high UID" in errors[0]["message"]
