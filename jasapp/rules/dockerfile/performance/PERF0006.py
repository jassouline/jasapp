import pytest
from jasapp.rules.base_rule import BaseRule


class PERF0006(BaseRule):
    """
    Rule to suggest using `COPY --chown` instead of a separate `RUN chown` instruction.
    """
    rule_type = "dockerfile"

    def __init__(self):
        super().__init__(
            friendly_name="UseCopyChown",
            name="PERF0006",
            description="Use `COPY --chown` instead of separate `RUN chown`",
            severity="info",
        )
        self.copy_lines = []
        self.chown_lines = []

    def check(self, instructions):
        """
        Checks for `COPY` instructions that could use `--chown` instead of a separate `RUN chown`.

        Args:
            instructions (list): A list of dictionaries containing parsed Dockerfile instructions.

        Returns:
            list: A list of errors found, each as a dictionary with line, message, and severity.
        """
        errors = []

        for instr in instructions:
            if instr["instruction"] == "FROM":
                self.copy_lines = []
                self.chown_lines = []
            elif instr["instruction"] == "COPY":
                if "--chown" not in instr["arguments"]:
                    self.copy_lines.append(instr["line"])
            elif instr["instruction"] == "RUN" and "chown" in instr["arguments"]:
                self.chown_lines.append(instr["line"])

        if self.copy_lines and self.chown_lines:
            errors.append({
                "line": self.copy_lines[0],  # Report on the first COPY instruction
                "message": "Use `COPY --chown` instead of separate `RUN chown`",
                "severity": self.severity,
                "doc_link": f"https://github.com/jassouline/jasapp/wiki/{self.name}"
            })

        return errors


@pytest.fixture
def use_copy_chown():
    return PERF0006()


def test_copy_without_chown_allows_copy_without_run_chown(use_copy_chown):
    parsed_content = [
        {"line": 1, "instruction": "COPY", "arguments": "source dest"},
    ]
    errors = use_copy_chown.check(parsed_content)
    assert len(errors) == 0


def test_copy_chown_allows_copy_with_chown(use_copy_chown):
    parsed_content = [
        {"line": 1, "instruction": "COPY", "arguments": "--chown=user:group source dest"},
    ]
    errors = use_copy_chown.check(parsed_content)
    assert len(errors) == 0


def test_copy_chown_detects_separate_run_chown(use_copy_chown):
    parsed_content = [
        {"line": 1, "instruction": "COPY", "arguments": "source dest"},
        {"line": 2, "instruction": "RUN", "arguments": "chown user:group dest"},
    ]
    errors = use_copy_chown.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "Use `COPY --chown` instead of separate `RUN chown`" in errors[0]["message"]


def test_copy_chown_ignores_other_instructions(use_copy_chown):
    parsed_content = [
        {"line": 1, "instruction": "ENV", "arguments": "MY_VAR=value"},
    ]
    errors = use_copy_chown.check(parsed_content)
    assert len(errors) == 0


def test_copy_chown_resets_by_from(use_copy_chown):
    parsed_content = [
        {"line": 1, "instruction": "FROM", "arguments": "ubuntu:22.04"},
        {"line": 2, "instruction": "COPY", "arguments": "source dest"},
        {"line": 3, "instruction": "RUN", "arguments": "chown user:group dest"},
        {"line": 4, "instruction": "FROM", "arguments": "alpine:latest"},
        {"line": 5, "instruction": "COPY", "arguments": "source dest"},
        {"line": 6, "instruction": "RUN", "arguments": "chown user:group dest"},
    ]
    errors = use_copy_chown.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 5
    assert "Use `COPY --chown` instead of separate `RUN chown`" in errors[0]["message"]
