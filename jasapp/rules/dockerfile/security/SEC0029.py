import pytest
from jasapp.rules.base_rule import BaseRule


class SEC0029(BaseRule):
    """
    Rule to ensure that a non-root `USER` instruction is used in the Dockerfile.
    """
    rule_type = "dockerfile"

    def __init__(self):
        super().__init__(
            friendly_name="CreateNonRootUser",
            name="SEC0029",
            description="No `USER` instruction found in the Dockerfile. Consider adding a non-root user.",
            severity="warning",
        )

    def check(self, instructions):
        """
        Checks if a non-root `USER` instruction is used in the Dockerfile.

        Args:
            instructions (list): A list of dictionaries containing parsed Dockerfile instructions.

        Returns:
            list: A list of errors found, each as a dictionary with line, message, and severity.
        """
        errors = []
        has_user = False

        for instr in instructions:
            if instr["instruction"] == "USER":
                if instr["arguments"].strip().lower() != "root":
                    has_user = True
                    break  # Found a non-root user, no need to continue checking

        if not has_user:
            errors.append({
                "line": 0,  # Report the error on line 0 (general error, not specific to a line)
                "message": "No `USER` instruction found in the Dockerfile. Consider adding a non-root user.",
                "severity": self.severity,
                "doc_link": f"https://github.com/jassouline/jasapp/wiki/{self.name}"
            })
        return errors


@pytest.fixture
def create_non_root_user():
    return SEC0029()


def test_non_root_user_detects_missing_user_instruction(create_non_root_user):
    parsed_content = [
        {"line": 1, "instruction": "FROM", "arguments": "ubuntu:latest"},
        {"line": 2, "instruction": "RUN", "arguments": "echo hello"},
    ]
    errors = create_non_root_user.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 0
    assert "No `USER` instruction found" in errors[0]["message"]


def test_non_root_user_allows_non_root_user(create_non_root_user):
    parsed_content = [
        {"line": 1, "instruction": "FROM", "arguments": "ubuntu:latest"},
        {"line": 2, "instruction": "USER", "arguments": "nobody"},
    ]
    errors = create_non_root_user.check(parsed_content)
    assert len(errors) == 0


def test_non_root_user_detect_root_user(create_non_root_user):
    parsed_content = [
        {"line": 1, "instruction": "FROM", "arguments": "ubuntu:latest"},
        {"line": 2, "instruction": "USER", "arguments": "root"},
    ]
    errors = create_non_root_user.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 0
    assert "No `USER` instruction found" in errors[0]["message"]


def test_non_root_user_allows_non_root_user_in_later_stage(create_non_root_user):
    parsed_content = [
        {"line": 1, "instruction": "FROM", "arguments": "ubuntu:latest"},
        {"line": 2, "instruction": "FROM", "arguments": "alpine:latest"},
        {"line": 3, "instruction": "USER", "arguments": "nobody"},
    ]
    errors = create_non_root_user.check(parsed_content)
    assert len(errors) == 0


def test_non_root_user_ignores_other_instructions(create_non_root_user):
    parsed_content = [
        {"line": 1, "instruction": "FROM", "arguments": "ubuntu:latest"},
        {"line": 2, "instruction": "RUN", "arguments": "echo hello"},
        {"line": 3, "instruction": "ENV", "arguments": "MY_VAR=value"},
    ]
    errors = create_non_root_user.check(parsed_content)
    assert len(errors) == 1
