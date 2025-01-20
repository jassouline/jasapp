import re
import pytest
from jasapp.rules.base_rule import BaseRule


class SEC0011(BaseRule):
    """
    Rule to detect insecure file permissions set with `chmod` in `RUN` instructions.
    """
    rule_type = "dockerfile"

    def __init__(self):
        super().__init__(
            friendly_name="InsecureChmod",
            name="SEC0011",
            description="Insecure file permissions set with `chmod` in `RUN` instruction",
            severity="warning",
        )

    def check(self, instructions):
        """
        Checks for insecure `chmod` commands in `RUN` instructions.

        Args:
            instructions (list): A list of dictionaries containing parsed Dockerfile instructions.

        Returns:
            list: A list of errors found, each as a dictionary with line, message, and severity.
        """
        errors = []

        for instr in instructions:
            if instr["instruction"] == "RUN":
                if self.is_insecure_chmod(instr["arguments"]):
                    errors.append({
                        "line": instr["line"],
                        "message": "Insecure file permissions set with `chmod` in `RUN` instruction. Avoid permissions like 777.",
                        "severity": self.severity,
                        "doc_link": f"https://github.com/jassouline/jasapp/wiki/{self.name}"
                    })

        return errors

    def is_insecure_chmod(self, command_string):
        """
        Checks if a command string contains an insecure `chmod` command.

        Args:
            command_string (str): The command string to check.

        Returns:
            bool: True if an insecure `chmod` command is found, False otherwise.
        """
        # Basic check for `chmod` command with potentially insecure permissions
        match = re.search(r"chmod\s+.*?(?<!\d)[0-7]?[6-7][6-7][6-7](?!\d)", command_string)
        if match:
            return True

        match = re.search(r"chmod.*?\s[a|u|g|o]\+rwx", command_string)

        if match:
            return True

        return False


@pytest.fixture
def insecure_chmod():
    return SEC0011()


def test_insecure_chmod_detects_777(insecure_chmod):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "chmod 777 /app/my_script.sh"},
    ]
    errors = insecure_chmod.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "Insecure file permissions set with `chmod`" in errors[0]["message"]


def test_insecure_chmod_detects_666(insecure_chmod):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "chmod 666 /app/my_file.txt"},
    ]
    errors = insecure_chmod.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "Insecure file permissions set with `chmod`" in errors[0]["message"]


def test_insecure_chmod_allows_755(insecure_chmod):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "chmod 755 /app/my_script.sh"},
    ]
    errors = insecure_chmod.check(parsed_content)
    assert len(errors) == 0


def test_insecure_chmod_allows_644(insecure_chmod):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "chmod 644 /app/my_file.txt"},
    ]
    errors = insecure_chmod.check(parsed_content)
    assert len(errors) == 0


def test_insecure_chmod_ignores_other_instructions(insecure_chmod):
    parsed_content = [
        {"line": 1, "instruction": "ENV", "arguments": "MY_VAR=value"},
    ]
    errors = insecure_chmod.check(parsed_content)
    assert len(errors) == 0


def test_insecure_chmod_detects_ugo_rwx(insecure_chmod):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "chmod u+rwx /app/my_script.sh"},
    ]
    errors = insecure_chmod.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "Insecure file permissions set with `chmod`" in errors[0]["message"]
