import pytest
from jasapp.rules.base_rule import BaseRule


class STX0004(BaseRule):
    rule_type = "dockerfile"

    """
    Rule to ensure that the WORKDIR instruction is used instead of 'cd' in RUN commands.
    """

    def __init__(self):
        super().__init__(
            friendly_name="UseWorkdirInsteadOfCd",
            hadolint="DL3003",
            name="STX0004",
            description="Use WORKDIR to switch to a directory instead of 'cd' in RUN instructions.",
            severity="warning",
        )

    def check(self, instructions):
        """
        Checks if the RUN instructions use 'cd' instead of WORKDIR.

        Args:
            instructions (list): A list of dictionaries containing parsed Dockerfile instructions.

        Returns:
            list: A list of errors found, each as a dictionary with line, message, and severity.
        """
        errors = []
        for instr in instructions:
            if instr["instruction"] == "RUN" and "cd " in instr["arguments"]:
                errors.append({
                    "line": instr["line"],
                    "message": "Avoid using 'cd' in RUN instructions. Use WORKDIR to switch directories.",
                    "severity": self.severity,
                    "doc_link": f"https://github.com/jassouline/jasapp/wiki/{self.name}"
                })
        return errors


# Test for STX0004
@pytest.fixture
def use_workdir_instead_of_cd():
    return STX0004()


def test_use_workdir_instead_of_cd_detects_cd(use_workdir_instead_of_cd):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "cd /app && npm install"},
        {"line": 2, "instruction": "RUN", "arguments": "cd /var && ls"},
    ]
    errors = use_workdir_instead_of_cd.check(parsed_content)
    assert len(errors) == 2
    assert errors[0]["message"] == "Avoid using 'cd' in RUN instructions. Use WORKDIR to switch directories."
    assert errors[0]["line"] == 1
    assert errors[1]["message"] == "Avoid using 'cd' in RUN instructions. Use WORKDIR to switch directories."
    assert errors[1]["line"] == 2


def test_use_workdir_instead_of_cd_allows_valid_commands(use_workdir_instead_of_cd):
    parsed_content = [
        {"line": 3, "instruction": "RUN", "arguments": "echo 'Hello World'"},
        {"line": 4, "instruction": "WORKDIR", "arguments": "/app"},
    ]
    errors = use_workdir_instead_of_cd.check(parsed_content)
    assert len(errors) == 0
