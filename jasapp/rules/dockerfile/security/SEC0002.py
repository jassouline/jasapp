import pytest
from jasapp.rules.base_rule import BaseRule


class SEC0002(BaseRule):
    rule_type = "dockerfile"

    """
    Rule to ensure that 'sudo' is not used in RUN instructions in Dockerfiles.
    """

    def __init__(self):
        super().__init__(
            friendly_name="AvoidSudoInRun",
            hadolint="DL3004",
            name="SEC0002",
            description="Do not use 'sudo' in RUN instructions as it leads to unpredictable behavior. \
                Use a tool like 'gosu' to enforce root instead.",
            severity="error",
        )

    def check(self, instructions):
        """
        Checks if the RUN instructions use 'sudo'.

        Args:
            instructions (list): A list of dictionaries containing parsed Dockerfile instructions.

        Returns:
            list: A list of errors found, each as a dictionary with line, message, and severity.
        """
        errors = []
        for instr in instructions:
            if instr["instruction"] == "RUN" and "sudo " in instr["arguments"]:
                errors.append({
                    "line": instr["line"],
                    "message": "Avoid using 'sudo' in RUN instructions. Use a tool like 'gosu' instead.",
                    "severity": self.severity,
                    "doc_link": f"https://github.com/jassouline/jasapp/wiki/{self.name}"
                })
        return errors


# Test for AvoidSudoInRun
@pytest.fixture
def avoid_sudo_in_run():
    return SEC0002()


def test_avoid_sudo_in_run_detects_sudo(avoid_sudo_in_run):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "sudo apt-get update"},
        {"line": 2, "instruction": "RUN", "arguments": "sudo apt-get install -y curl"},
    ]
    errors = avoid_sudo_in_run.check(parsed_content)
    assert len(errors) == 2
    assert errors[0]["message"] == "Avoid using 'sudo' in RUN instructions. Use a tool like 'gosu' instead."
    assert errors[0]["line"] == 1
    assert errors[1]["message"] == "Avoid using 'sudo' in RUN instructions. Use a tool like 'gosu' instead."
    assert errors[1]["line"] == 2


def test_avoid_sudo_in_run_allows_valid_commands(avoid_sudo_in_run):
    parsed_content = [
        {"line": 3, "instruction": "RUN", "arguments": "apt-get update && apt-get install -y python3"},
        {"line": 4, "instruction": "RUN", "arguments": "echo 'Hello World'"},
    ]
    errors = avoid_sudo_in_run.check(parsed_content)
    assert len(errors) == 0
