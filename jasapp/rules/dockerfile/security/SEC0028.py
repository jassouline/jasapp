import pytest
from jasapp.rules.base_rule import BaseRule


class SEC0028(BaseRule):
    """
    Rule to ensure that port 22 is not exposed in `EXPOSE` instructions.
    """
    rule_type = "dockerfile"

    def __init__(self):
        super().__init__(
            friendly_name="NoExposePort22",
            name="SEC0028",
            description="Port 22 is exposed, which can pose a security risk.",
            severity="warning"
        )

    def check(self, instructions):
        """
        Checks if `EXPOSE` instructions expose port 22.

        Args:
            instructions (list): A list of dictionaries containing parsed Dockerfile instructions.

        Returns:
            list: A list of errors found, each as a dictionary with line, message, and severity.
        """
        errors = []

        for instr in instructions:
            if instr["instruction"] == "EXPOSE" and "22" in instr["arguments"].split():
                errors.append({
                    "line": instr["line"],
                    "message": "Port 22 is exposed, which can pose a security risk.",
                    "severity": self.severity,
                    "doc_link": f"https://github.com/jassouline/jasapp/wiki/{self.name}"
                })

        return errors


@pytest.fixture
def no_expose_port_22():
    return SEC0028()


def test_expose_port_22_detects_port_22(no_expose_port_22):
    parsed_content = [
        {"line": 1, "instruction": "EXPOSE", "arguments": "22"},
    ]
    errors = no_expose_port_22.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "Port 22 is exposed" in errors[0]["message"]


def test_expose_port_22_detects_port_22_among_other_ports(no_expose_port_22):
    parsed_content = [
        {"line": 1, "instruction": "EXPOSE", "arguments": "80 22 443"},
    ]
    errors = no_expose_port_22.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "Port 22 is exposed" in errors[0]["message"]


def test_expose_port_22_allows_other_ports(no_expose_port_22):
    parsed_content = [
        {"line": 1, "instruction": "EXPOSE", "arguments": "80 443"},
    ]
    errors = no_expose_port_22.check(parsed_content)
    assert len(errors) == 0


def test_expose_port_22_ignores_other_instructions(no_expose_port_22):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "echo hello"},
    ]
    errors = no_expose_port_22.check(parsed_content)
    assert len(errors) == 0
