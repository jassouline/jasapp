import pytest
from jasapp.rules.base_rule import BaseRule


class STX0023(BaseRule):
    """
    Rule to ensure FROM aliases (stage names) are unique.
    """
    rule_type = "dockerfile"

    def __init__(self):
        super().__init__(
            friendly_name="FromAliasesMustBeUnique",
            hadolint="DL3024",
            name="STX0023",
            description="FROM aliases (stage names) must be unique.",
            severity="error",
        )

    def check(self, instructions):
        """
        Checks if FROM aliases are unique.

        Args:
            instructions (list): A list of dictionaries containing parsed Dockerfile instructions.

        Returns:
            list: A list of errors found, each as a dictionary with line, message, and severity.
        """
        from_aliases = set()
        errors = []

        for instr in instructions:
            if instr["instruction"] == "FROM":
                arguments = instr["arguments"].split()
                if len(arguments) > 2 and arguments[-2].upper() == "AS":
                    alias = arguments[-1].lower()  # Convert alias to lowercase for comparison
                    if alias in from_aliases:
                        errors.append({
                            "line": instr["line"],
                            "message": "FROM aliases (stage names) must be unique.",
                            "severity": self.severity,
                            "doc_link": f"https://github.com/jassouline/jasapp/wiki/{self.name}"
                        })
                    else:
                        from_aliases.add(alias)

        return errors


@pytest.fixture
def from_aliases_must_be_unique():
    return STX0023()


def test_from_aliases_must_be_unique_detects_duplicate_aliases(from_aliases_must_be_unique):
    parsed_content = [
        {"line": 1, "instruction": "FROM", "arguments": "alpine:latest AS builder"},
        {"line": 2, "instruction": "FROM", "arguments": "ubuntu:latest AS builder"},
    ]
    errors = from_aliases_must_be_unique.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 2
    assert errors[0]["message"] == "FROM aliases (stage names) must be unique."


def test_from_aliases_must_be_unique_allows_unique_aliases(from_aliases_must_be_unique):
    parsed_content = [
        {"line": 1, "instruction": "FROM", "arguments": "alpine:latest AS builder"},
        {"line": 2, "instruction": "FROM", "arguments": "ubuntu:latest AS runtime"},
    ]
    errors = from_aliases_must_be_unique.check(parsed_content)
    assert len(errors) == 0


def test_from_aliases_must_be_unique_ignores_unnamed_stages(from_aliases_must_be_unique):
    parsed_content = [
        {"line": 1, "instruction": "FROM", "arguments": "alpine:latest"},
        {"line": 2, "instruction": "FROM", "arguments": "ubuntu:latest"},
    ]
    errors = from_aliases_must_be_unique.check(parsed_content)
    assert len(errors) == 0


def test_from_aliases_must_be_unique_handles_mixed_cases(from_aliases_must_be_unique):
    parsed_content = [
        {"line": 1, "instruction": "FROM", "arguments": "alpine:latest AS BUILDER"},
        {"line": 2, "instruction": "FROM", "arguments": "ubuntu:latest AS builder"},
    ]
    errors = from_aliases_must_be_unique.check(parsed_content)
    assert len(errors) == 1  # Now it should detect the error
    assert errors[0]["line"] == 2
    assert errors[0]["message"] == "FROM aliases (stage names) must be unique."
