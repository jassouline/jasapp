import pytest
from jasapp.rules.base_rule import BaseRule


class STX0053(BaseRule):
    """
    Rule to ensure that Dockerfiles begin with `FROM`, `ARG`, a comment, or a parser directive.
    """
    rule_type = "dockerfile"

    def __init__(self):
        super().__init__(
            friendly_name="InvalidInstructionOrder",
            hadolint="DL3061",
            name="STX0053",
            description="Invalid instruction order. Dockerfile must begin with `FROM`, `ARG`, a comment, or a parser directive.",
            severity="error",
        )
        self.valid_start = False
        self.has_from = False

    def check(self, instructions):
        errors = []
        self.valid_start = False
        self.has_from = False

        for instr in instructions:
            if not self.valid_start:
                if instr["instruction"] in ["FROM", "#", "# syntax", "# escape"]:
                    self.valid_start = True
                    if instr["instruction"] == "FROM":
                        self.has_from = True
                elif instr["instruction"] == "ARG":
                    self.valid_start = True
                else:
                    errors.append({
                        "line": instr["line"],
                        "message": "Invalid instruction order. Dockerfile must begin with `FROM`, `ARG`, a comment, or a parser directive.",
                        "severity": self.severity,
                        "doc_link": f"https://github.com/jassouline/jasapp/wiki/{self.name}"
                    })
            elif instr["instruction"] == "FROM":
                self.has_from = True
            elif instr["instruction"] not in ["ARG", "#", "# syntax", "# escape", "FROM"] and not self.has_from:
                errors.append({
                    "line": instr["line"],
                    "message": "Invalid instruction order. `ARG` instructions are only allowed before the first `FROM`",
                    "severity": self.severity,
                    "doc_link": f"https://github.com/jassouline/jasapp/wiki/{self.name}"
                })
                self.valid_start = False  # Reset valid_start when an invalid instruction is found after a valid start
        return errors


@pytest.fixture
def invalid_instruction_order():
    return STX0053()


def test_invalid_order_detects_invalid_first_instruction(invalid_instruction_order):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "echo hello"},
    ]
    errors = invalid_instruction_order.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "Invalid instruction order" in errors[0]["message"]


def test_invalid_order_allows_from_first(invalid_instruction_order):
    parsed_content = [
        {"line": 1, "instruction": "FROM", "arguments": "ubuntu:latest"},
    ]
    errors = invalid_instruction_order.check(parsed_content)
    assert len(errors) == 0


def test_invalid_order_allows_arg_first(invalid_instruction_order):
    parsed_content = [
        {"line": 1, "instruction": "ARG", "arguments": "VERSION=latest"},
        {"line": 2, "instruction": "FROM", "arguments": "ubuntu:$VERSION"},
    ]
    errors = invalid_instruction_order.check(parsed_content)
    assert len(errors) == 0


def test_invalid_order_allows_comment_first(invalid_instruction_order):
    parsed_content = [
        {"line": 1, "instruction": "#", "arguments": "This is a comment"},
        {"line": 2, "instruction": "FROM", "arguments": "ubuntu:latest"},
    ]
    errors = invalid_instruction_order.check(parsed_content)
    assert len(errors) == 0


def test_invalid_order_allows_parser_directive_first(invalid_instruction_order):
    parsed_content = [
        {"line": 1, "instruction": "# syntax", "arguments": "docker/dockerfile:experimental"},
        {"line": 2, "instruction": "FROM", "arguments": "ubuntu:latest"},
    ]
    errors = invalid_instruction_order.check(parsed_content)
    assert len(errors) == 0


def test_invalid_order_detects_invalid_order_after_from(invalid_instruction_order):
    parsed_content = [
        {"line": 1, "instruction": "FROM", "arguments": "ubuntu:latest"},
        {"line": 2, "instruction": "RUN", "arguments": "echo hello"},
        {"line": 3, "instruction": "ARG", "arguments": "TEST=test"}
    ]
    errors = invalid_instruction_order.check(parsed_content)
    assert len(errors) == 0


def test_invalid_order_allows_parser_directive_before_from(invalid_instruction_order):
    parsed_content = [
        {"line": 1, "instruction": "ARG", "arguments": "TEST=test"},
        {"line": 2, "instruction": "# syntax", "arguments": "docker/dockerfile:experimental"},
        {"line": 3, "instruction": "FROM", "arguments": "ubuntu:latest"},
        {"line": 4, "instruction": "RUN", "arguments": "echo hello"},
        {"line": 5, "instruction": "ARG", "arguments": "TEST=test"}
    ]
    errors = invalid_instruction_order.check(parsed_content)
    assert len(errors) == 0


def test_invalid_order_allows_arg_after_from(invalid_instruction_order):
    parsed_content = [
        {"line": 1, "instruction": "FROM", "arguments": "ubuntu:latest"},
        {"line": 2, "instruction": "ARG", "arguments": "TEST=test"}
    ]
    errors = invalid_instruction_order.check(parsed_content)
    assert len(errors) == 0
