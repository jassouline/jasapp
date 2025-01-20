import pytest
from jasapp.rules.base_rule import BaseRule


class STX0054(BaseRule):
    """
    Rule to ensure that the deprecated `MAINTAINER` instruction is not used.
    """
    rule_type = "dockerfile"

    def __init__(self):
        super().__init__(
            friendly_name="MaintainerDeprecated",
            hadolint="DL4000",
            name="STX0054",
            description="`MAINTAINER` is deprecated",
            severity="error",
        )

    def check(self, instructions):
        """
        Checks if the `MAINTAINER` instruction is used in the Dockerfile.

        Args:
            instructions (list): A list of dictionaries containing parsed Dockerfile instructions.

        Returns:
            list: A list of errors found, each as a dictionary with line, message, and severity.
        """
        errors = []

        for instr in instructions:
            if instr["instruction"] == "MAINTAINER":
                errors.append({
                    "line": instr["line"],
                    "message": "`MAINTAINER` is deprecated",
                    "severity": self.severity,
                    "doc_link": f"https://github.com/jassouline/jasapp/wiki/{self.name}"
                })

        return errors


@pytest.fixture
def maintainer_deprecated():
    return STX0054()


def test_maintainer_deprecated_detects_maintainer(maintainer_deprecated):
    parsed_content = [
        {"line": 1, "instruction": "MAINTAINER", "arguments": "john.doe@example.com"},
    ]
    errors = maintainer_deprecated.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "`MAINTAINER` is deprecated" in errors[0]["message"]


def test_maintainer_deprecated_ignores_other_instructions(maintainer_deprecated):
    parsed_content = [
        {"line": 1, "instruction": "FROM", "arguments": "ubuntu:latest"},
        {"line": 2, "instruction": "RUN", "arguments": "apt-get update"},
    ]
    errors = maintainer_deprecated.check(parsed_content)
    assert len(errors) == 0
