import pytest
from jasapp.rules.base_rule import BaseRule


class STX0003(BaseRule):
    rule_type = "dockerfile"

    """
    Rule to ensure that certain bash commands that make no sense in a Docker container are not used.
    """

    INVALID_COMMANDS = {
        "ssh", "vim", "shutdown", "service", "ps",
        "free", "top", "kill", "mount", "ifconfig"
    }

    def __init__(self):
        super().__init__(
            friendly_name="AvoidInvalidCommands",
            hadolint="DL3001",
            name="STX0003",
            description=(
                "Avoid using commands like `ssh`, `vim`, `shutdown`, `service`, `ps`, `free`, "
                "`top`, `kill`, `mount`, or `ifconfig` in Dockerfiles as they are not "
                "applicable in a containerized environment."
            ),
            severity="info",
        )

    def check(self, instructions):
        """
        Checks for invalid commands in RUN instructions.

        Args:
            instructions (list): A list of dictionaries containing parsed Dockerfile instructions.

        Returns:
            list: A list of errors found, each as a dictionary with line, message, and severity.
        """
        errors = []
        for instr in instructions:
            if instr["instruction"] == "RUN":
                commands = instr["arguments"].split()
                for command in commands:
                    if command in self.INVALID_COMMANDS:
                        errors.append({
                            "line": instr["line"],
                            "message": f"Command `{command}` is not recommended in Docker containers.",
                            "severity": self.severity,
                            "doc_link": f"https://github.com/jassouline/jasapp/wiki/{self.name}"
                        })
        return errors


@pytest.fixture
def avoid_invalid_commands():
    return STX0003()


# Test STX0003
def test_avoid_invalid_commands_detects_invalid(avoid_invalid_commands):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "ssh user@host"},
        {"line": 2, "instruction": "RUN", "arguments": "vim /etc/config"},
        {"line": 3, "instruction": "RUN", "arguments": "top"}
    ]
    errors = avoid_invalid_commands.check(parsed_content)
    assert len(errors) == 3
    assert errors[0]["message"] == "Command `ssh` is not recommended in Docker containers."
    assert errors[0]["line"] == 1
    assert errors[1]["message"] == "Command `vim` is not recommended in Docker containers."
    assert errors[1]["line"] == 2
    assert errors[2]["message"] == "Command `top` is not recommended in Docker containers."
    assert errors[2]["line"] == 3


def test_avoid_invalid_commands_allows_valid(avoid_invalid_commands):
    parsed_content = [
        {"line": 4, "instruction": "RUN", "arguments": "apt-get update && apt-get install -y python3"},
        {"line": 5, "instruction": "RUN", "arguments": "echo Hello World"}
    ]
    errors = avoid_invalid_commands.check(parsed_content)
    assert len(errors) == 0
