import re
import pytest
from datetime import datetime
from jasapp.rules.base_rule import BaseRule


class STX0048(BaseRule):
    """
    Rule to ensure that label values, for specific required labels, are valid RFC3339 timestamps.
    """
    rule_type = "dockerfile"

    def __init__(self, rfc3339_labels=None):
        super().__init__(
            friendly_name="LabelValueIsRFC3339",
            hadolint="DL3052",
            name="STX0048",
            description="Label value is not a valid RFC3339 timestamp.",
            severity="warning",
        )
        self.rfc3339_labels = set(rfc3339_labels) if rfc3339_labels else set()

    def check(self, instructions):
        """
        Checks if label values, for specific required labels, are valid RFC3339 timestamps.

        Args:
            instructions (list): A list of dictionaries containing parsed Dockerfile instructions.

        Returns:
            list: A list of errors found, each as a dictionary with line, message, and severity.
        """
        errors = []

        # Handle multi-line instructions by joining lines ending with \
        i = 0
        while i < len(instructions) - 1:
            if instructions[i]["instruction"] == "LABEL" and instructions[i]["arguments"].endswith("\\"):
                instructions[i]["arguments"] = instructions[i]["arguments"][:-1] + " " + instructions[i+1]["arguments"]
                # Update the line number of the next instruction to point to the first line of the multiline instruction
                instructions[i+1]["line"] = instructions[i]["line"]
                instructions[i+1]["instruction"] = "SKIP"
            i += 1

        for instr in instructions:
            if instr["instruction"] == "SKIP":
                continue
            elif instr["instruction"] == "LABEL":
                for key, value in self.parse_label_instruction(instr["arguments"]):
                    if key in self.rfc3339_labels and not self.is_valid_rfc3339(value):
                        errors.append({
                            "line": instr["line"],
                            "message": f"Label '{key}' has an invalid RFC3339 timestamp value: '{value}'.",
                            "severity": self.severity,
                            "doc_link": f"https://github.com/jassouline/jasapp/wiki/{self.name}"
                        })

        return errors

    def parse_label_instruction(self, arguments):
        """
        Parses a LABEL instruction's arguments and returns a list of key-value pairs.
        Handles multi-line and quoted arguments.

        Args:
            arguments (str): The arguments of the LABEL instruction.

        Returns:
            list: A list of tuples, each representing a key-value pair.
        """
        pairs = []

        # Remove any trailing comments from the arguments string
        arguments = arguments.split("#")[0].strip()

        # Use regular expression to split arguments, handling quoted values
        parts = re.findall(r'(?:[^\s"]|"(?:\\.|[^"])*")+', arguments)

        for part in parts:
            if "=" in part:
                key, value = part.split("=", 1)
                # Remove quotes from key and value if present
                key = key.strip().strip('"').strip("'")
                value = value.strip().strip('"').strip("'")
                pairs.append((key, value))
            else:
                # Handle keys without an explicit value
                pairs.append((part.strip(), ""))

        return pairs

    def is_valid_rfc3339(self, timestamp_string):
        """
        Checks if a string is a valid RFC3339 timestamp.

        Args:
            timestamp_string (str): The string to check.

        Returns:
            bool: True if the string is a valid RFC3339 timestamp, False otherwise.
        """
        if not timestamp_string:
            return True
        try:
            datetime.fromisoformat(timestamp_string.replace("Z", "+00:00"))
            return True
        except ValueError:
            return False


@pytest.fixture
def label_value_is_rfc3339():
    return STX0048(rfc3339_labels=["created", "updated"])


def test_label_value_is_rfc3339_detects_invalid_timestamp(label_value_is_rfc3339):
    parsed_content = [
        {"line": 1, "instruction": "LABEL", "arguments": "maintainer='test' website='invalid_url'"},
    ]
    errors = label_value_is_rfc3339.check(parsed_content)
    assert len(errors) == 0


def test_label_value_is_rfc3339_allows_valid_timestamp(label_value_is_rfc3339):
    parsed_content = [
        {"line": 1, "instruction": "LABEL", "arguments": "created=2023-10-27T10:00:00Z"},
    ]
    errors = label_value_is_rfc3339.check(parsed_content)
    assert len(errors) == 0


def test_label_value_is_rfc3339_ignores_unspecified_labels(label_value_is_rfc3339):
    parsed_content = [
        {"line": 1, "instruction": "LABEL", "arguments": "version='not_a_timestamp'"},
    ]
    errors = label_value_is_rfc3339.check(parsed_content)
    assert len(errors) == 0


def test_label_value_is_rfc3339_ignores_other_instructions(label_value_is_rfc3339):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "echo hello"},
    ]
    errors = label_value_is_rfc3339.check(parsed_content)
    assert len(errors) == 0


def test_label_value_is_rfc3339_detects_invalid_timestamp_multiline(label_value_is_rfc3339):
    parsed_content = [
        {"line": 1, "instruction": "LABEL", "arguments": "maintainer='test' \\"},
        {"line": 2, "instruction": "SKIP", "arguments": "created='invalid' \\"},
        {"line": 3, "instruction": "SKIP", "arguments": "source='https://example.com'"},
    ]
    errors = label_value_is_rfc3339.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "Label 'created' has an invalid RFC3339 timestamp value" in errors[0]["message"]
