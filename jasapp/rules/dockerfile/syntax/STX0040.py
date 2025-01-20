import pytest
from jasapp.rules.base_rule import BaseRule


class STX0040(BaseRule):
    """
    Rule to ensure `ONBUILD`, `FROM`, and `MAINTAINER` are not used within an `ONBUILD` instruction.
    """
    rule_type = "dockerfile"

    def __init__(self):
        super().__init__(
            friendly_name="NoOnbuildFromMaintainerInOnbuild",
            hadolint="DL3043",
            name="STX0040",
            description="`ONBUILD`, `FROM`, or `MAINTAINER` should not be triggered from within `ONBUILD` instruction.",
            severity="error",
        )

    def check(self, instructions):
        """
        Checks if `ONBUILD`, `FROM`, or `MAINTAINER` are used within an `ONBUILD` instruction.

        Args:
            instructions (list): A list of dictionaries containing parsed Dockerfile instructions.

        Returns:
            list: A list of errors found, each as a dictionary with line, message, and severity.
        """
        errors = []

        for instr in instructions:
            if instr["instruction"] == "ONBUILD":
                if instr["arguments"].startswith("ONBUILD"):
                    errors.append({
                        "line": instr["line"],
                        "message": "`ONBUILD` triggered from within `ONBUILD` instruction.",
                        "severity": self.severity,
                        "doc_link": f"https://github.com/jassouline/jasapp/wiki/{self.name}"
                    })
                elif instr["arguments"].startswith("FROM"):
                    errors.append({
                        "line": instr["line"],
                        "message": "`FROM` triggered from within `ONBUILD` instruction.",
                        "severity": self.severity,
                        "doc_link": f"https://github.com/jassouline/jasapp/wiki/{self.name}"
                    })
                elif instr["arguments"].startswith("MAINTAINER"):
                    errors.append({
                        "line": instr["line"],
                        "message": "`MAINTAINER` triggered from within `ONBUILD` instruction.",
                        "severity": self.severity,
                        "doc_link": f"https://github.com/jassouline/jasapp/wiki/{self.name}"
                    })
        return errors


@pytest.fixture
def no_onbuild_from_maintainer_in_onbuild():
    return STX0040()


def test_no_onbuild_from_maintainer_detects_onbuild_in_onbuild(no_onbuild_from_maintainer_in_onbuild):
    parsed_content = [
        {"line": 1, "instruction": "ONBUILD", "arguments": "ONBUILD RUN echo hello"},
    ]
    errors = no_onbuild_from_maintainer_in_onbuild.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "`ONBUILD` triggered from within `ONBUILD` instruction" in errors[0]["message"]


def test_no_onbuild_from_maintainer_detects_from_in_onbuild(no_onbuild_from_maintainer_in_onbuild):
    parsed_content = [
        {"line": 1, "instruction": "ONBUILD", "arguments": "FROM ubuntu:latest"},
    ]
    errors = no_onbuild_from_maintainer_in_onbuild.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "`FROM` triggered from within `ONBUILD` instruction" in errors[0]["message"]


def test_no_onbuild_from_maintainer_detects_maintainer_in_onbuild(no_onbuild_from_maintainer_in_onbuild):
    parsed_content = [
        {"line": 1, "instruction": "ONBUILD", "arguments": "MAINTAINER john.doe@example.com"},
    ]
    errors = no_onbuild_from_maintainer_in_onbuild.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "`MAINTAINER` triggered from within `ONBUILD` instruction" in errors[0]["message"]


def test_no_onbuild_from_maintainer_allows_other_instructions_in_onbuild(no_onbuild_from_maintainer_in_onbuild):
    parsed_content = [
        {"line": 1, "instruction": "ONBUILD", "arguments": "RUN echo hello"},
        {"line": 2, "instruction": "ONBUILD", "arguments": "ADD . /app"},
    ]
    errors = no_onbuild_from_maintainer_in_onbuild.check(parsed_content)
    assert len(errors) == 0


def test_no_onbuild_from_maintainer_ignores_instructions_outside_onbuild(no_onbuild_from_maintainer_in_onbuild):
    parsed_content = [
        {"line": 1, "instruction": "FROM", "arguments": "ubuntu:latest"},
        {"line": 2, "instruction": "MAINTAINER", "arguments": "john.doe@example.com"},
        {"line": 3, "instruction": "RUN", "arguments": "echo hello"},
    ]
    errors = no_onbuild_from_maintainer_in_onbuild.check(parsed_content)
    assert len(errors) == 0
