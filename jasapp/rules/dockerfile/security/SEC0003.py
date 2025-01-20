import re
import pytest
from jasapp.rules.base_rule import BaseRule


class SEC0003(BaseRule):
    rule_type = "dockerfile"

    """
    Rule to ensure that a HEALTHCHECK instruction is provided
    and that it is correctly configured.
    """

    def __init__(self):
        super().__init__(
            friendly_name="UseHealthcheckInstruction",
            hadolint="CISDI0006",
            name="SEC0003",
            description="Add a HEALTHCHECK dockerfile instruction to perform the health check on running containers.",
            severity="info",
        )

    def check(self, instructions):
        """
        Checks if there is a HEALTHCHECK instruction and if it's correctly configured.

        Args:
            instructions (list): A list of dictionaries containing parsed Dockerfile instructions.

        Returns:
            list: A list of errors found, each as a dictionary with line, message, and severity.
        """
        errors = []
        has_healthcheck = False
        for instr in instructions:
            # Check if HEALTHCHECK is set correct syntax
            if instr["instruction"] == "HEALTHCHECK":
                has_healthcheck = True
                # Check for correct syntax
                match = re.match(r"^(?:--interval=.*? )?(?:--timeout=.*? )?CMD .*", instr["arguments"])
                if instr["arguments"] == "NONE":
                    errors.append({
                        "line": instr["line"],
                        "message": "HEALTHCHECK must not be set to NONE. Expected format: HEALTHCHECK [OPTIONS] CMD command",
                        "severity": self.severity,
                        "doc_link": f"https://github.com/jassouline/jasapp/wiki/{self.name}"
                    })
                elif not match:
                    errors.append({
                        "line": instr["line"],
                        "message": f"Invalid HEALTHCHECK syntax: {instr['arguments']}. Expected format: HEALTHCHECK [OPTIONS] CMD command",
                        "severity": self.severity,
                        "doc_link": f"https://github.com/jassouline/jasapp/wiki/{self.name}"
                    })

        if not has_healthcheck:
            errors.append({
                "line": 0,
                "message": "Add a HEALTHCHECK dockerfile instruction to perform the health check on running containers.",
                "severity": self.severity,
                "doc_link": f"https://github.com/jassouline/jasapp/wiki/{self.name}"
            })
        return errors


# Test for UseHealthcheckInstruction
@pytest.fixture
def use_healthcheck_instruction():
    return SEC0003()


def test_use_healthcheck_instruction_set(use_healthcheck_instruction):
    parsed_content = [
        {"line": 1, "instruction": "FROM", "arguments": "ubuntu:22.04"},
        {"line": 2, "instruction": "RUN", "arguments": "apt-get update && apt-get install -y curl"},
        {"line": 3, "instruction": "HEALTHCHECK", "arguments": "--interval=5m --timeout=3s CMD curl -f http://localhost/ || exit 1"}
    ]
    errors = use_healthcheck_instruction.check(parsed_content)
    assert len(errors) == 0


def test_not_healthcheck_instruction(use_healthcheck_instruction):
    parsed_content = [
        {"line": 1, "instruction": "FROM", "arguments": "ubuntu:22.04"},
        {"line": 2, "instruction": "RUN", "arguments": "apt-get update && apt-get install -y curl"},
    ]
    errors = use_healthcheck_instruction.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["message"] == "Add a HEALTHCHECK dockerfile instruction to perform the health check on running containers."
    assert errors[0]["line"] == 0


def test_invalid_healthcheck_syntax(use_healthcheck_instruction):
    parsed_content = [
        {"line": 1, "instruction": "FROM", "arguments": "ubuntu:22.04"},
        {"line": 2, "instruction": "RUN", "arguments": "apt-get update && apt-get install -y curl"},
        {"line": 3, "instruction": "HEALTHCHECK", "arguments": "--interval=5m --timeout=3s INVALID_COMMAND"}
    ]
    errors = use_healthcheck_instruction.check(parsed_content)
    assert len(errors) == 1
    message = "Invalid HEALTHCHECK syntax: --interval=5m --timeout=3s INVALID_COMMAND. Expected format: HEALTHCHECK [OPTIONS] CMD command"
    assert errors[0]["message"] == message
    assert errors[0]["line"] == 3


def test_healthcheck_set_on_none(use_healthcheck_instruction):
    parsed_content = [
        {"line": 1, "instruction": "FROM", "arguments": "ubuntu:22.04"},
        {"line": 2, "instruction": "RUN", "arguments": "apt-get update && apt-get install -y curl"},
        {"line": 3, "instruction": "HEALTHCHECK", "arguments": "NONE"}
    ]
    errors = use_healthcheck_instruction.check(parsed_content)
    print(errors)
    assert len(errors) == 1
    assert errors[0]["message"] == "HEALTHCHECK must not be set to NONE. Expected format: HEALTHCHECK [OPTIONS] CMD command"
    assert errors[0]["line"] == 3
