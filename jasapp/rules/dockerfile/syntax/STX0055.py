import pytest
from jasapp.rules.base_rule import BaseRule


class STX0055(BaseRule):
    """
    Rule to ensure that only one `CMD` instruction is used in a Dockerfile.
    Only the last `CMD` will take effect if multiple are present.
    """
    rule_type = "dockerfile"

    def __init__(self):
        super().__init__(
            friendly_name="OnlyOneCMD",
            hadolint="DL4003",
            name="STX0055",
            description="Multiple `CMD` instructions found. If you list more than one `CMD` then only the last `CMD` will take effect.",
            severity="warning",
        )
        self.cmd_count = 0
        self.cmd_line = None

    def check(self, instructions):
        """
        Checks for multiple `CMD` instructions in a Dockerfile.

        Args:
            instructions (list): A list of dictionaries containing parsed Dockerfile instructions.

        Returns:
            list: A list of errors found, each as a dictionary with line, message, and severity.
        """
        errors = []

        for instr in instructions:
            if instr["instruction"] == "FROM":
                self.cmd_count = 0  # Reset on new FROM instruction
                self.cmd_line = None
            elif instr["instruction"] == "CMD":
                if self.cmd_count > 0:
                    errors.append({
                        "line": instr["line"],
                        "message": "Multiple `CMD` instructions found. Only the last `CMD` will take effect.",
                        "severity": self.severity,
                        "doc_link": f"https://github.com/jassouline/jasapp/wiki/{self.name}"
                    })
                else:
                    self.cmd_count = 1
                    self.cmd_line = instr["line"]

        return errors


@pytest.fixture
def only_one_cmd():
    return STX0055()


def test_multiple_cmd_detects_multiple_cmds(only_one_cmd):
    parsed_content = [
        {"line": 1, "instruction": "CMD", "arguments": '["executable", "param1"]'},
        {"line": 2, "instruction": "CMD", "arguments": '["executable", "param2"]'},
    ]
    errors = only_one_cmd.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 2
    assert "Multiple `CMD` instructions found." in errors[0]["message"]


def test_multiple_cmd_allows_single_cmd(only_one_cmd):
    parsed_content = [
        {"line": 1, "instruction": "CMD", "arguments": '["executable", "param1"]'},
    ]
    errors = only_one_cmd.check(parsed_content)
    assert len(errors) == 0


def test_multiple_cmd_ignores_other_instructions(only_one_cmd):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "echo hello"},
        {"line": 2, "instruction": "ENV", "arguments": "MY_VAR=value"},
    ]
    errors = only_one_cmd.check(parsed_content)
    assert len(errors) == 0


def test_multiple_cmd_resets_on_from(only_one_cmd):
    parsed_content = [
        {"line": 1, "instruction": "FROM", "arguments": "ubuntu:latest"},
        {"line": 2, "instruction": "CMD", "arguments": '["executable", "param1"]'},
        {"line": 3, "instruction": "FROM", "arguments": "alpine:latest"},
        {"line": 4, "instruction": "CMD", "arguments": '["executable", "param2"]'},
        {"line": 5, "instruction": "CMD", "arguments": '["executable", "param3"]'},
    ]
    errors = only_one_cmd.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 5
