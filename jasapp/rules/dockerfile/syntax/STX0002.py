import pytest
from jasapp.rules.base_rule import BaseRule


class STX0002(BaseRule):
    """
    Rule to ensure that the 'latest' tag is not used in Docker images.
    """
    rule_type = "dockerfile"

    def __init__(self):
        super().__init__(
            name="STX0002",
            friendly_name="AvoidLatestTag",
            description="Avoid using the 'latest' tag in Docker images.",
            severity="warning",
        )

    def check(self, instructions):
        """
        Checks for the use of the 'latest' tag in Dockerfiles.

        Args:
            instructions (list): A list of dictionaries containing parsed Dockerfile instructions.

        Returns:
            list: A list of errors found, each as a dictionary with line, message, and severity.
        """
        errors = []
        for instr in instructions:
            if instr["instruction"] == "FROM" and "latest" in instr["arguments"]:
                errors.append({
                    "line": instr["line"],
                    "message": f"'{instr['arguments']}' uses the 'latest' tag. Specify a fixed version instead.",
                    "severity": self.severity,
                    "doc_link": f"https://github.com/jassouline/jasapp/wiki/{self.name}"
                })
        return errors


@pytest.fixture
def avoid_latest_tag():
    return STX0002()


# Test for AvoidLatestTag
def test_avoid_latest_tag_detects_latest(avoid_latest_tag):
    parsed_content = [{"line": 1, "instruction": "FROM", "arguments": "ubuntu:latest"}]
    errors = avoid_latest_tag.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["message"] == "'ubuntu:latest' uses the 'latest' tag. Specify a fixed version instead."
    assert errors[0]["line"] == 1


def test_avoid_latest_tag_allows_fixed_tag(avoid_latest_tag):
    parsed_content = [{"line": 1, "instruction": "FROM", "arguments": "ubuntu:20.04"}]
    errors = avoid_latest_tag.check(parsed_content)
    assert len(errors) == 0
