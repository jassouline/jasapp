import pytest
from jasapp.rules.base_rule import BaseRule


class STX0012(BaseRule):
    """
    Rule to ensure that there are no multiple HEALTHCHECK instructions in a Dockerfile.
    """
    rule_type = "dockerfile"

    def __init__(self):
        super().__init__(
            friendly_name="SingleHealthcheck",
            hadolint="DL3012",
            name="STX0012",
            description="Ensure there is only one HEALTHCHECK instruction in the Dockerfile.",
            severity="error",
        )

    def check(self, instructions):
        """
        Checks if multiple HEALTHCHECK instructions are present in the Dockerfile.

        Args:
            instructions (list): A list of dictionaries containing parsed Dockerfile instructions.

        Returns:
            list: A list of errors found, each as a dictionary with line, message, and severity.
        """
        errors = []
        healthcheck_count = 0

        for instr in instructions:
            if instr["instruction"] == "HEALTHCHECK":
                healthcheck_count += 1
                if healthcheck_count > 1:
                    errors.append({
                        "line": instr["line"],
                        "message": "Multiple HEALTHCHECK instructions found. Use only one HEALTHCHECK instruction.",
                        "severity": self.severity,
                        "doc_link": f"https://github.com/jassouline/jasapp/wiki/{self.name}"
                    })

        return errors


@pytest.fixture
def single_healthcheck():
    return STX0012()


def test_single_healthcheck_detects_multiple_healthchecks(single_healthcheck):
    parsed_content = [
        {"line": 1, "instruction": "HEALTHCHECK", "arguments": "--interval=30s CMD curl -f http://localhost || exit 1"},
        {"line": 2, "instruction": "HEALTHCHECK", "arguments": "--interval=30s CMD curl -f http://localhost || exit 1"},
    ]
    errors = single_healthcheck.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 2
    assert errors[0]["message"] == "Multiple HEALTHCHECK instructions found. Use only one HEALTHCHECK instruction."


def test_single_healthcheck_allows_single_healthcheck(single_healthcheck):
    parsed_content = [
        {"line": 1, "instruction": "HEALTHCHECK", "arguments": "--interval=30s CMD curl -f http://localhost || exit 1"},
    ]
    errors = single_healthcheck.check(parsed_content)
    assert len(errors) == 0


def test_single_healthcheck_allows_no_healthcheck(single_healthcheck):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "apt-get update && apt-get install -y curl"},
    ]
    errors = single_healthcheck.check(parsed_content)
    assert len(errors) == 0
