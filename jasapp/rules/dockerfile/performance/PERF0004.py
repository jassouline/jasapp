import pytest
from jasapp.rules.base_rule import BaseRule


class PERF0004(BaseRule):
    """
    Rule to detect multiple consecutive `RUN` instructions and suggest consolidation.
    """
    rule_type = "dockerfile"

    def __init__(self):
        super().__init__(
            friendly_name="MultipleConsecutiveRunInstructions",
            hadolint="DL3059",
            name="PERF0004",
            description="Multiple consecutive `RUN` instructions. Consider consolidation.",
            severity="info",
        )
        self.consecutive_runs = 0
        self.first_line = None

    def check(self, instructions):
        """
        Checks for multiple consecutive `RUN` instructions.

        Args:
            instructions (list): A list of dictionaries containing parsed Dockerfile instructions.

        Returns:
            list: A list of errors found, each as a dictionary with line, message, and severity.
        """
        errors = []

        for instr in instructions:
            if instr["instruction"] == "RUN":
                if self.consecutive_runs == 0:
                    self.first_line = instr["line"]
                self.consecutive_runs += 1
            else:
                if self.consecutive_runs > 1:
                    errors.append({
                        "line": self.first_line,
                        "message": "Multiple consecutive `RUN` instructions. Consider consolidation.",
                        "severity": self.severity,
                        "doc_link": f"https://github.com/jassouline/jasapp/wiki/{self.name}"
                    })
                self.consecutive_runs = 0
                self.first_line = None

        # Check for errors at the end of the file
        if self.consecutive_runs > 1:
            errors.append({
                "line": self.first_line,
                "message": "Multiple consecutive `RUN` instructions. Consider consolidation.",
                "severity": self.severity,
                "doc_link": f"https://github.com/jassouline/jasapp/wiki/{self.name}"
            })

        return errors


@pytest.fixture
def multiple_consecutive_run_instructions():
    return PERF0004()


def test_multiple_runs_detects_consecutive_runs(multiple_consecutive_run_instructions):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "apt-get update"},
        {"line": 2, "instruction": "RUN", "arguments": "apt-get install -y curl"},
        {"line": 3, "instruction": "RUN", "arguments": "apt-get install -y git"},
    ]
    errors = multiple_consecutive_run_instructions.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "Multiple consecutive `RUN` instructions." in errors[0]["message"]


def test_multiple_runs_allows_single_run(multiple_consecutive_run_instructions):
    parsed_content = [
        {"line": 1, "instruction": "FROM", "arguments": "ubuntu:latest"},
        {"line": 2, "instruction": "RUN", "arguments": "apt-get update"},
        {"line": 3, "instruction": "ENV", "arguments": "MY_VAR=value"},
    ]
    errors = multiple_consecutive_run_instructions.check(parsed_content)
    assert len(errors) == 0


def test_multiple_runs_resets_after_other_instruction(multiple_consecutive_run_instructions):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "apt-get update"},
        {"line": 2, "instruction": "ENV", "arguments": "MY_VAR=value"},
        {"line": 3, "instruction": "RUN", "arguments": "apt-get install -y curl"},
    ]
    errors = multiple_consecutive_run_instructions.check(parsed_content)
    assert len(errors) == 0


def test_multiple_runs_detects_consecutive_runs_at_end_of_file(multiple_consecutive_run_instructions):
    parsed_content = [
        {"line": 1, "instruction": "FROM", "arguments": "ubuntu:latest"},
        {"line": 2, "instruction": "RUN", "arguments": "apt-get update"},
        {"line": 3, "instruction": "RUN", "arguments": "apt-get install -y curl"},
    ]
    errors = multiple_consecutive_run_instructions.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 2
    assert "Multiple consecutive `RUN` instructions." in errors[0]["message"]
