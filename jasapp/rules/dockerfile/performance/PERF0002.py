import re
import pytest
from jasapp.rules.base_rule import BaseRule


class PERF0002(BaseRule):
    """
    Rule to ensure `wget` in RUN instructions uses `--progress=dot:giga` or `-q` or `-nv` for better output.
    """
    rule_type = "dockerfile"

    def __init__(self):
        super().__init__(
            friendly_name="UseWgetWithProgressBarOrQuiet",
            hadolint="DL3047",
            name="PERF0002",
            description="Avoid use of wget without progress bar. Use `wget --progress=dot:giga <url>`.\n"
                        "Or consider using `-q` or `-nv` (shorthands for `--quiet` or `--no-verbose`).",
            severity="info",
        )

    def check(self, instructions):
        """
        Checks if `wget` in RUN instructions uses `--progress=dot:giga` or `-q` or `-nv`.

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
                    if self.is_wget_without_progress_or_quiet(command):
                        errors.append({
                            "line": instr["line"],
                            "message": "Avoid use of wget without progress bar. Use `wget --progress=dot:giga <url>`.\n"
                                       "Or consider using `-q` or `-nv` (shorthands for `--quiet` or `--no-verbose`).",
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

    def is_wget_without_progress_or_quiet(self, command_string):
        """
        Checks if a command string is a `wget` command without `--progress=dot:giga` or `-q` or `-nv`.

        Args:
            command_string (str): The command string to check.

        Returns:
            bool: True if it's a `wget` command without progress bar or quiet flags, False otherwise.
        """
        if "wget" not in command_string:
            return False

        words = re.split(r"\s+", command_string)
        if "--progress=dot:giga" in words:
            return False

        if any(word in ["-q", "--quiet", "-nv", "--no-verbose"] for word in words):
            return False

        return True


@pytest.fixture
def use_wget_with_progress_bar_or_quiet():
    return PERF0002()


def test_wget_without_progress_or_quiet_detects_missing_flags(use_wget_with_progress_bar_or_quiet):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "wget example.com/file.zip"},
    ]
    errors = use_wget_with_progress_bar_or_quiet.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "Avoid use of wget without progress bar" in errors[0]["message"]


def test_wget_with_progress_allows_progress_flag(use_wget_with_progress_bar_or_quiet):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "wget --progress=dot:giga example.com/file.zip"},
    ]
    errors = use_wget_with_progress_bar_or_quiet.check(parsed_content)
    assert len(errors) == 0


def test_wget_with_quiet_allows_quiet_flag(use_wget_with_progress_bar_or_quiet):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "wget -q example.com/file.zip"},
    ]
    errors = use_wget_with_progress_bar_or_quiet.check(parsed_content)
    assert len(errors) == 0


def test_wget_with_no_verbose_allows_no_verbose_flag(use_wget_with_progress_bar_or_quiet):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "wget -nv example.com/file.zip"},
    ]
    errors = use_wget_with_progress_bar_or_quiet.check(parsed_content)
    assert len(errors) == 0


def test_wget_with_no_verbose_long_allows_no_verbose_flag(use_wget_with_progress_bar_or_quiet):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "wget --no-verbose example.com/file.zip"},
    ]
    errors = use_wget_with_progress_bar_or_quiet.check(parsed_content)
    assert len(errors) == 0


def test_wget_with_quiet_long_allows_quiet_flag(use_wget_with_progress_bar_or_quiet):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "wget --quiet example.com/file.zip"},
    ]
    errors = use_wget_with_progress_bar_or_quiet.check(parsed_content)
    assert len(errors) == 0


def test_wget_without_progress_ignores_other_commands(use_wget_with_progress_bar_or_quiet):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "echo hello"},
    ]
    errors = use_wget_with_progress_bar_or_quiet.check(parsed_content)
    assert len(errors) == 0


def test_wget_without_progress_handles_complex_commands(use_wget_with_progress_bar_or_quiet):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "wget example.com/file.zip && echo hello"},
    ]
    errors = use_wget_with_progress_bar_or_quiet.check(parsed_content)
    assert len(errors) == 1
    assert "Avoid use of wget without progress bar" in errors[0]["message"]


def test_wget_without_progress_handles_complex_commands_with_semicolon(use_wget_with_progress_bar_or_quiet):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "wget example.com/file.zip; echo hello"},
    ]
    errors = use_wget_with_progress_bar_or_quiet.check(parsed_content)
    assert len(errors) == 1
    assert "Avoid use of wget without progress bar" in errors[0]["message"]


def test_wget_without_progress_handles_output_file_flags(use_wget_with_progress_bar_or_quiet):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "wget -o log.txt example.com/file.zip"},
    ]
    errors = use_wget_with_progress_bar_or_quiet.check(parsed_content)
    assert len(errors) == 1

    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "wget -a log.txt example.com/file.zip"},
    ]
    errors = use_wget_with_progress_bar_or_quiet.check(parsed_content)
    assert len(errors) == 1

    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "wget --output-file=log.txt example.com/file.zip"},
    ]
    errors = use_wget_with_progress_bar_or_quiet.check(parsed_content)
    assert len(errors) == 1

    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "wget --append-output=log.txt example.com/file.zip"},
    ]
    errors = use_wget_with_progress_bar_or_quiet.check(parsed_content)
    assert len(errors) == 1
