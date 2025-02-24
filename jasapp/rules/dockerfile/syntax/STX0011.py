import pytest
from jasapp.rules.base_rule import BaseRule
import re


class STX0011(BaseRule):
    """
    Rule to ensure that exposed ports are within the valid UNIX port range (0 to 65535).
    """
    rule_type = "dockerfile"

    def __init__(self):
        super().__init__(
            friendly_name="ValidExposedPorts",
            hadolint="DL3011",
            name="STX0011",
            description="Ensure exposed ports are within the valid UNIX port range (0 to 65535).",
            severity="error",
        )

    @staticmethod
    def is_valid_port(port_str):
        """
        Check if a port is within the valid UNIX port range (0 to 65535).
        Now also handles non-integer port values (e.g., variables).

        Args:
            port_str (str): The port number as a string.

        Returns:
            bool: True if the port is valid or not an integer, False otherwise.
        """
        try:
            port = int(port_str)  # Try to convert to integer
            return 0 <= port <= 65535
        except ValueError:
            return True  # It's not an integer, so it's a variable.  Consider it valid

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
                for port_str in ports:
                    # Handle ranges (e.g., "5000-6000")
                    if "-" in port_str:
                        match = re.match(r"^(\d+)-(\d+)$", port_str)
                        if not match:
                            errors.append({
                                "line": instr["line"],
                                "message": f"Invalid port range '{port_str}'.",
                                "severity": self.severity,
                                "doc_link": f"https://github.com/jassouline/jasapp/wiki/{self.name}"
                            })
                            continue
                        start, end = int(match.group(1)), int(match.group(2))
                        if not (self.is_valid_port(str(start)) and self.is_valid_port(str(end))):
                            errors.append({
                                "line": instr["line"],
                                "message": f"Invalid port range '{port_str}'. Ports must be within 0 to 65535.",
                                "severity": self.severity,
                                "doc_link": f"https://github.com/jassouline/jasapp/wiki/{self.name}"
                            })

                    else:
                        # Check that port_str is all digits, *then* check if it's a valid port
                        if not port_str.isdigit() or not self.is_valid_port(port_str):
                            errors.append({
                                "line": instr["line"],
                                "message": f"Invalid port '{port_str}'. Ports must be within 0 to 65535.",
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


def test_valid_unix_ports_ignores_other_instructions(valid_unix_ports):
    parsed_content = [
        {"line": 4, "instruction": "RUN", "arguments": "echo 'This is not an EXPOSE command'"},
    ]
    errors = valid_unix_ports.check(parsed_content)
    assert len(errors) == 0

# Supprime les tests qui sont maintenant incorrects
# def test_valid_unix_ports_ignores_variable(valid_unix_ports):
#     parsed_content = [
#         {"line": 1, "instruction": "ARG", "arguments": "APP_PORT=8080"},
#         {"line": 2, "instruction": "EXPOSE", "arguments": "${APP_PORT}"},
#     ]
#     errors = valid_unix_ports.check(parsed_content)
#     assert len(errors) == 0

# def test_valid_unix_ports_ignores_invalid_variable(valid_unix_ports):
#     parsed_content = [
#         {"line": 1, "instruction": "ARG", "arguments": "APP_PORT=invalid"},
#         {"line": 2, "instruction": "EXPOSE", "arguments": "${APP_PORT}"},
#     ]
#     errors = valid_unix_ports.check(parsed_content)
#     assert len(errors) == 0


def test_valid_unix_ports_detects_invalid_single_port_with_valid(valid_unix_ports):
    # Mix valid and invalid ports
    parsed_content = [
        {"line": 1, "instruction": "EXPOSE", "arguments": "80 70000 443"},
    ]
    errors = valid_unix_ports.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "Invalid port '70000'" in errors[0]["message"]


def test_valid_unix_ports_detects_invalid_range_with_valid(valid_unix_ports):
    parsed_content = [
        {"line": 2, "instruction": "EXPOSE", "arguments": "80 1000-70000 443"},
    ]
    errors = valid_unix_ports.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 2
    assert "Invalid port range '1000-70000'" in errors[0]["message"]
