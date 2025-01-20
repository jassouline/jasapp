import re
import pytest
from jasapp.rules.base_rule import BaseRule


class PERF0005(BaseRule):
    """
    Rule to ensure that either `wget` or `curl` is used in a single `RUN` instruction, but not both.
    """
    rule_type = "dockerfile"

    def __init__(self):
        super().__init__(
            friendly_name="UseWgetOrCurl",
            hadolint="DL4001",
            name="PERF0005",
            description="Either use `wget` or `curl` but not both",
            severity="warning",
        )
        self.reset_state()

    def reset_state(self):
        self.has_wget_or_curl = set()

    def check(self, instructions):
        """
        Checks if both `wget` and `curl` are used in the same `RUN` instruction.

        Args:
            instructions (list): A list of dictionaries containing parsed Dockerfile instructions.

        Returns:
            list: A list of errors found, each as a dictionary with line, message, and severity.
        """
        errors = []

        for instr in instructions:
            if instr["instruction"] == "FROM":
                self.reset_state()

            if instr["instruction"] == "RUN":
                commands = self.split_commands(instr["arguments"])
                for command in commands:
                    if self.has_wget_and_curl(command):
                        errors.append({
                            "line": instr["line"],
                            "message": "Either use `wget` or `curl` but not both",
                            "severity": self.severity,
                            "doc_link": f"https://github.com/jassouline/jasapp/wiki/{self.name}"
                        })

                self.has_wget_or_curl = set()

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

    def has_wget_and_curl(self, command_string):
        """
        Checks if a command string contains both `wget` and `curl`.

        Args:
            command_string (str): The command string to check.

        Returns:
            bool: True if both `wget` and `curl` are found, False otherwise.
        """

        words = re.split(r"\s+", command_string)

        for word in words:
            if word == "wget" or word == "curl":
                self.has_wget_or_curl.add(word)

        return len(self.has_wget_or_curl) > 1


@pytest.fixture
def use_wget_or_curl():
    return PERF0005()


def test_wget_and_curl_detects_both(use_wget_or_curl):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "wget example.com && curl example.com"},
    ]
    errors = use_wget_or_curl.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "Either use `wget` or `curl` but not both" in errors[0]["message"]


def test_wget_and_curl_allows_one(use_wget_or_curl):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "wget example.com"},
    ]
    errors = use_wget_or_curl.check(parsed_content)
    assert len(errors) == 0


def test_wget_and_curl_ignores_other_commands(use_wget_or_curl):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "echo hello"},
    ]
    errors = use_wget_or_curl.check(parsed_content)
    assert len(errors) == 0


def test_wget_and_curl_handles_complex_commands(use_wget_or_curl):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "wget example.com && apt-get update"},
    ]
    errors = use_wget_or_curl.check(parsed_content)
    assert len(errors) == 0


def test_wget_and_curl_handles_complex_commands_with_semicolon(use_wget_or_curl):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "curl example.com; apt-get update"},
    ]
    errors = use_wget_or_curl.check(parsed_content)
    assert len(errors) == 0


def test_wget_and_curl_reset_state_on_from(use_wget_or_curl):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "wget example.com && curl example.com"},
        {"line": 2, "instruction": "FROM", "arguments": "ubuntu:latest"},
        {"line": 3, "instruction": "RUN", "arguments": "wget example.com && curl example.com"},
    ]
    errors = use_wget_or_curl.check(parsed_content)
    assert len(errors) == 2
