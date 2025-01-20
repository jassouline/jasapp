import pytest
from jasapp.rules.base_rule import BaseRule


class STX0011(BaseRule):
    """
    Rule to ensure that exposed ports are within the valid UNIX port range (0 to 65535).
    """
    rule_type = "dockerfile"

    def __init__(self):
        super().__init__(
            friendly_name="ValidUnixPorts",
            hadolint="DL3011",
            name="STX0011",
            description="Ensure exposed ports are within the valid UNIX port range (0 to 65535).",
            severity="error",
        )

    @staticmethod
    def is_valid_port(port):
        """
        Check if a port is within the valid UNIX port range (0 to 65535).

        Args:
            port (int): The port number.

        Returns:
            bool: True if the port is valid, False otherwise.
        """
        return 0 <= port <= 65535

    def check(self, instructions):
        """
        Check if EXPOSE instructions use valid UNIX ports.

        Args:
            instructions (list): A list of dictionaries containing parsed Dockerfile instructions.

        Returns:
            list: A list of errors found, each as a dictionary with line, message, and severity.
        """
        errors = []

        for instr in instructions:
            if instr["instruction"] == "EXPOSE":
                ports = instr["arguments"].split()
                for port in ports:
                    # Handle individual ports and ranges (e.g., "8080", "5000-6000")
                    if "-" in port:
                        start, end = map(int, port.split("-"))
                        if not (self.is_valid_port(start) and self.is_valid_port(end)):
                            errors.append({
                                "line": instr["line"],
                                "message": f"Invalid port range '{port}'. Ports must be within 0 to 65535.",
                                "severity": self.severity,
                                "doc_link": f"https://github.com/jassouline/jasapp/wiki/{self.name}"
                            })
                    else:
                        if not self.is_valid_port(int(port)):
                            errors.append({
                                "line": instr["line"],
                                "message": f"Invalid port '{port}'. Ports must be within 0 to 65535.",
                                "severity": self.severity,
                                "doc_link": f"https://github.com/jassouline/jasapp/wiki/{self.name}"
                            })

        return errors


@pytest.fixture
def valid_unix_ports():
    return STX0011()


# Test Cases
def test_valid_unix_ports_detects_invalid_single_port(valid_unix_ports):
    parsed_content = [
        {"line": 1, "instruction": "EXPOSE", "arguments": "70000"},
    ]
    errors = valid_unix_ports.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert errors[0]["message"] == "Invalid port '70000'. Ports must be within 0 to 65535."


def test_valid_unix_ports_detects_invalid_range(valid_unix_ports):
    parsed_content = [
        {"line": 2, "instruction": "EXPOSE", "arguments": "10000-70000"},
    ]
    errors = valid_unix_ports.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 2
    assert errors[0]["message"] == "Invalid port range '10000-70000'. Ports must be within 0 to 65535."


def test_valid_unix_ports_allows_valid_ports(valid_unix_ports):
    parsed_content = [
        {"line": 3, "instruction": "EXPOSE", "arguments": "8080 5000-6000"},
    ]
    errors = valid_unix_ports.check(parsed_content)
    assert len(errors) == 0


def test_valid_unix_ports_ignores_non_expose(valid_unix_ports):
    parsed_content = [
        {"line": 4, "instruction": "RUN", "arguments": "echo 'This is not an EXPOSE command'"},
    ]
    errors = valid_unix_ports.check(parsed_content)
    assert len(errors) == 0
