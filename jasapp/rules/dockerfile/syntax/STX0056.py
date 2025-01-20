import pytest
from jasapp.rules.base_rule import BaseRule


class STX0056(BaseRule):
    """
    Rule to ensure that only one `ENTRYPOINT` instruction is used in a Dockerfile.
    Only the last `ENTRYPOINT` will take effect if multiple are present.
    """
    rule_type = "dockerfile"

    def __init__(self):
        super().__init__(
            friendly_name="OnlyOneEntrypoint",
            hadolint="DL4004",
            name="STX0056",
            description="Multiple `ENTRYPOINT` instructions found. If you list more than one `ENTRYPOINT` then only the last `ENTRYPOINT` will take effect.",
            severity="error",
        )
        self.entrypoint_count = 0
        self.entrypoint_line = None

    def check(self, instructions):
        """
        Checks for multiple `ENTRYPOINT` instructions in a Dockerfile.

        Args:
            instructions (list): A list of dictionaries containing parsed Dockerfile instructions.

        Returns:
            list: A list of errors found, each as a dictionary with line, message, and severity.
        """
        errors = []

        for instr in instructions:
            if instr["instruction"] == "FROM":
                self.entrypoint_count = 0  # Reset on new FROM instruction
                self.entrypoint_line = None
            elif instr["instruction"] == "ENTRYPOINT":
                if self.entrypoint_count > 0:
                    errors.append({
                        "line": instr["line"],
                        "message": "Multiple `ENTRYPOINT` instructions found. Only the last `ENTRYPOINT` will take effect.",
                        "severity": self.severity,
                        "doc_link": f"https://github.com/jassouline/jasapp/wiki/{self.name}"
                    })
                else:
                    self.entrypoint_count = 1
                    self.entrypoint_line = instr["line"]

        return errors


@pytest.fixture
def only_one_entrypoint():
    return STX0056()


def test_multiple_entrypoint_detects_multiple_entrypoints(only_one_entrypoint):
    parsed_content = [
        {"line": 1, "instruction": "ENTRYPOINT", "arguments": '["executable", "param1"]'},
        {"line": 2, "instruction": "ENTRYPOINT", "arguments": '["executable", "param2"]'},
    ]
    errors = only_one_entrypoint.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 2
    assert "Multiple `ENTRYPOINT` instructions found." in errors[0]["message"]


def test_multiple_entrypoint_allows_single_entrypoint(only_one_entrypoint):
    parsed_content = [
        {"line": 1, "instruction": "ENTRYPOINT", "arguments": '["executable", "param1"]'},
    ]
    errors = only_one_entrypoint.check(parsed_content)
    assert len(errors) == 0


def test_multiple_entrypoint_ignores_other_instructions(only_one_entrypoint):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "echo hello"},
        {"line": 2, "instruction": "ENV", "arguments": "MY_VAR=value"},
    ]
    errors = only_one_entrypoint.check(parsed_content)
    assert len(errors) == 0


def test_multiple_entrypoint_resets_on_from(only_one_entrypoint):
    parsed_content = [
        {"line": 1, "instruction": "FROM", "arguments": "ubuntu:latest"},
        {"line": 2, "instruction": "ENTRYPOINT", "arguments": '["executable", "param1"]'},
        {"line": 3, "instruction": "FROM", "arguments": "alpine:latest"},
        {"line": 4, "instruction": "ENTRYPOINT", "arguments": '["executable", "param2"]'},
        {"line": 5, "instruction": "ENTRYPOINT", "arguments": '["executable", "param3"]'},
    ]
    errors = only_one_entrypoint.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 5
