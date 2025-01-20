import re
import pytest
from jasapp.rules.base_rule import BaseRule


class SEC0012(BaseRule):
    """
    Rule to detect potentially dangerous shell commands in `RUN` instructions, such as
    `cat /dev/zero > file` or `dd if=/dev/random`.
    """
    rule_type = "dockerfile"

    def __init__(self):
        super().__init__(
            friendly_name="PotentiallyDangerousCommand",
            name="SEC0012",
            description="Potentially dangerous shell command used in `RUN` instruction",
            severity="warning",
        )

    def check(self, instructions):
        """
        Checks for potentially dangerous shell commands in `RUN` instructions.

        Args:
            instructions (list): A list of dictionaries containing parsed Dockerfile instructions.

        Returns:
            list: A list of errors found, each as a dictionary with line, message, and severity.
        """
        errors = []

        for instr in instructions:
            if instr["instruction"] == "RUN":
                if self.is_dangerous_command(instr["arguments"]):
                    errors.append({
                        "line": instr["line"],
                        "message": "Potentially dangerous shell command used in `RUN` instruction",
                        "severity": self.severity,
                        "doc_link": f"https://github.com/jassouline/jasapp/wiki/{self.name}"
                    })

        return errors

    def is_dangerous_command(self, command_string):
        """
        Checks if a command string contains potentially dangerous shell commands.

        Args:
            command_string (str): The command string to check.

        Returns:
            bool: True if a potentially dangerous command is found, False otherwise.
        """
        # List of potentially dangerous commands or patterns
        dangerous_patterns = [
            r"cat\s+/dev/zero\s+>",  # Writing infinite zeros to a file
            r"dd\s+if=/dev/random",  # Using dd with /dev/random (can be slow and unpredictable)
            r"dd\s+if=/dev/zero",    # Similar to cat /dev/zero
            r">\s*/dev/null",  # Redirection to /dev/null
            # Add more patterns as needed
        ]

        for pattern in dangerous_patterns:
            if re.search(pattern, command_string):
                return True

        return False


@pytest.fixture
def potentially_dangerous_command():
    return SEC0012()


def test_dangerous_command_detects_cat_dev_zero(potentially_dangerous_command):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "cat /dev/zero > /tmp/large_file"},
    ]
    errors = potentially_dangerous_command.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "Potentially dangerous shell command" in errors[0]["message"]


def test_dangerous_command_detects_dd_dev_random(potentially_dangerous_command):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "dd if=/dev/random of=/tmp/random_data count=100"},
    ]
    errors = potentially_dangerous_command.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "Potentially dangerous shell command" in errors[0]["message"]


def test_dangerous_command_detects_null_redirection(potentially_dangerous_command):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "cat  > /dev/null"},
    ]
    errors = potentially_dangerous_command.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "Potentially dangerous shell command" in errors[0]["message"]


def test_dangerous_command_allows_safe_commands(potentially_dangerous_command):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "echo hello"},
    ]
    errors = potentially_dangerous_command.check(parsed_content)
    assert len(errors) == 0


def test_dangerous_command_ignores_other_instructions(potentially_dangerous_command):
    parsed_content = [
        {"line": 1, "instruction": "ENV", "arguments": "MY_VAR=value"},
    ]
    errors = potentially_dangerous_command.check(parsed_content)
    assert len(errors) == 0
