import pytest
from jasapp.rules.base_rule import BaseRule


class STX0064(BaseRule):
    """
    Rule to detect `RUN` instructions after `CMD` or `ENTRYPOINT` in a Dockerfile.
    """
    rule_type = "dockerfile"

    def __init__(self):
        super().__init__(
            friendly_name="RunAfterCmdOrEntrypoint",
            name="STX0064",
            description="`RUN` instruction after `CMD` or `ENTRYPOINT`",
            severity="warning",
        )
        self.cmd_or_entrypoint_found = False

    def check(self, instructions):
        """
        Checks for `RUN` instructions after `CMD` or `ENTRYPOINT`.

        Args:
            instructions (list): A list of dictionaries containing parsed Dockerfile instructions.

        Returns:
            list: A list of errors found, each as a dictionary with line, message, and severity.
        """
        errors = []

        for instr in instructions:
            if instr["instruction"] in ["CMD", "ENTRYPOINT"]:
                self.cmd_or_entrypoint_found = True
            elif instr["instruction"] == "RUN" and self.cmd_or_entrypoint_found:
                errors.append({
                    "line": instr["line"],
                    "message": "`RUN` instruction after `CMD` or `ENTRYPOINT`",
                    "severity": self.severity,
                    "doc_link": f"https://github.com/jassouline/jasapp/wiki/{self.name}"
                })
            elif instr["instruction"] == "FROM":
                self.cmd_or_entrypoint_found = False

        return errors


@pytest.fixture
def run_after_cmd_or_entrypoint():
    return STX0064()


def test_run_after_cmd_or_entrypoint_detects_run_after_cmd(run_after_cmd_or_entrypoint):
    parsed_content = [
        {"line": 1, "instruction": "FROM", "arguments": "ubuntu:latest"},
        {"line": 2, "instruction": "CMD", "arguments": '["executable", "param1"]'},
        {"line": 3, "instruction": "RUN", "arguments": "echo hello"},
    ]
    errors = run_after_cmd_or_entrypoint.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 3
    assert "`RUN` instruction after `CMD` or `ENTRYPOINT`" in errors[0]["message"]


def test_run_after_cmd_or_entrypoint_detects_run_after_entrypoint(run_after_cmd_or_entrypoint):
    parsed_content = [
        {"line": 1, "instruction": "FROM", "arguments": "ubuntu:latest"},
        {"line": 2, "instruction": "ENTRYPOINT", "arguments": '["executable", "param1"]'},
        {"line": 3, "instruction": "RUN", "arguments": "echo hello"},
    ]
    errors = run_after_cmd_or_entrypoint.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 3
    assert "`RUN` instruction after `CMD` or `ENTRYPOINT`" in errors[0]["message"]


def test_run_after_cmd_or_entrypoint_allows_run_before_cmd_or_entrypoint(run_after_cmd_or_entrypoint):
    parsed_content = [
        {"line": 1, "instruction": "FROM", "arguments": "ubuntu:latest"},
        {"line": 2, "instruction": "RUN", "arguments": "echo hello"},
        {"line": 3, "instruction": "CMD", "arguments": '["executable", "param1"]'},
    ]
    errors = run_after_cmd_or_entrypoint.check(parsed_content)
    assert len(errors) == 0


def test_run_after_cmd_or_entrypoint_ignores_other_instructions(run_after_cmd_or_entrypoint):
    parsed_content = [
        {"line": 1, "instruction": "FROM", "arguments": "ubuntu:latest"},
        {"line": 2, "instruction": "ENV", "arguments": "MY_VAR=value"},
        {"line": 3, "instruction": "CMD", "arguments": '["executable", "param1"]'},
    ]
    errors = run_after_cmd_or_entrypoint.check(parsed_content)
    assert len(errors) == 0


def test_run_after_cmd_or_entrypoint_resets_on_from(run_after_cmd_or_entrypoint):
    parsed_content = [
        {"line": 1, "instruction": "FROM", "arguments": "ubuntu:latest"},
        {"line": 2, "instruction": "CMD", "arguments": '["executable", "param1"]'},
        {"line": 3, "instruction": "RUN", "arguments": "echo hello"},
        {"line": 4, "instruction": "FROM", "arguments": "alpine:latest"},
        {"line": 5, "instruction": "CMD", "arguments": '["executable", "param2"]'},
        {"line": 6, "instruction": "RUN", "arguments": "echo hello again"},
    ]
    errors = run_after_cmd_or_entrypoint.check(parsed_content)
    assert len(errors) == 2  # On s'attend maintenant à deux erreurs
    assert errors[0]["line"] == 3
    assert errors[1]["line"] == 6
    assert "`RUN` instruction after `CMD` or `ENTRYPOINT`" in errors[0]["message"]
