import pytest
from jasapp.rules.base_rule import BaseRule


class STX0063(BaseRule):
    """
    Rule to detect `USER` instruction before `WORKDIR`, `COPY`, or `ADD` instructions within the same stage.
    """
    rule_type = "dockerfile"

    def __init__(self):
        super().__init__(
            friendly_name="UserBeforeWorkdirCopyAdd",
            name="STX0063",
            description="`USER` instruction used before `WORKDIR`, `COPY`, or `ADD` within the same stage",
            severity="warning",
        )
        self.workdir_copy_add_found = False

    def check(self, instructions):
        """
        Checks for `USER` instructions before `WORKDIR`, `COPY`, or `ADD` instructions within the same stage.

        Args:
            instructions (list): A list of dictionaries containing parsed Dockerfile instructions.

        Returns:
            list: A list of errors found, each as a dictionary with line, message, and severity.
        """
        errors = []

        for instr in instructions:
            if instr["instruction"] == "FROM":
                # Reset state for new FROM instruction
                self.workdir_copy_add_found = False
            elif instr["instruction"] in ["WORKDIR", "COPY", "ADD"]:
                self.workdir_copy_add_found = True
            elif instr["instruction"] == "USER" and not self.workdir_copy_add_found:
                errors.append({
                    "line": instr["line"],
                    "message": "`USER` instruction used before `WORKDIR`, `COPY`, or `ADD` within the same stage",
                    "severity": self.severity,
                    "doc_link": f"https://github.com/jassouline/jasapp/wiki/{self.name}"
                })

        return errors


@pytest.fixture
def user_before_workdir_copy_add():
    return STX0063()


def test_user_before_workdir_copy_add_detects_user_before_workdir(user_before_workdir_copy_add):
    parsed_content = [
        {"line": 1, "instruction": "FROM", "arguments": "ubuntu:latest"},
        {"line": 2, "instruction": "USER", "arguments": "testuser"},
        {"line": 3, "instruction": "WORKDIR", "arguments": "/app"},
    ]
    errors = user_before_workdir_copy_add.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 2
    assert "`USER` instruction used before `WORKDIR`, `COPY`, or `ADD`" in errors[0]["message"]


def test_user_before_workdir_copy_add_detects_user_before_copy(user_before_workdir_copy_add):
    parsed_content = [
        {"line": 1, "instruction": "FROM", "arguments": "ubuntu:latest"},
        {"line": 2, "instruction": "USER", "arguments": "testuser"},
        {"line": 3, "instruction": "COPY", "arguments": "source dest"},
    ]
    errors = user_before_workdir_copy_add.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 2
    assert "`USER` instruction used before `WORKDIR`, `COPY`, or `ADD`" in errors[0]["message"]


def test_user_before_workdir_copy_add_detects_user_before_add(user_before_workdir_copy_add):
    parsed_content = [
        {"line": 1, "instruction": "FROM", "arguments": "ubuntu:latest"},
        {"line": 2, "instruction": "USER", "arguments": "testuser"},
        {"line": 3, "instruction": "ADD", "arguments": "source dest"},
    ]
    errors = user_before_workdir_copy_add.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 2
    assert "`USER` instruction used before `WORKDIR`, `COPY`, or `ADD`" in errors[0]["message"]


def test_user_before_workdir_copy_add_allows_user_after_workdir_copy_add(user_before_workdir_copy_add):
    parsed_content = [
        {"line": 1, "instruction": "FROM", "arguments": "ubuntu:latest"},
        {"line": 2, "instruction": "WORKDIR", "arguments": "/app"},
        {"line": 3, "instruction": "USER", "arguments": "testuser"},
    ]
    errors = user_before_workdir_copy_add.check(parsed_content)
    assert len(errors) == 0


def test_user_before_workdir_copy_add_ignores_other_instructions(user_before_workdir_copy_add):
    parsed_content = [
        {"line": 1, "instruction": "FROM", "arguments": "ubuntu:latest"},
        {"line": 2, "instruction": "RUN", "arguments": "echo hello"},
        {"line": 3, "instruction": "ENV", "arguments": "MY_VAR=value"},
    ]
    errors = user_before_workdir_copy_add.check(parsed_content)
    assert len(errors) == 0
