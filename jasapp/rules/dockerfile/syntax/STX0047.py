import re
import pytest
from urllib.parse import urlparse
from jasapp.rules.base_rule import BaseRule


class STX0047(BaseRule):
    """
    Rule to ensure that label values, for specific required labels, are valid URLs.
    """
    rule_type = "dockerfile"

    def __init__(self, url_labels=None):
        super().__init__(
            friendly_name="LabelValueIsURL",
            hadolint="DL3052",
            name="STX0047",
            description="Label value is not a valid URL.",
            severity="warning",
        )
        self.url_labels = set(url_labels) if url_labels else set()

    def check(self, instructions):
        errors = []

        # Handle multi-line instructions by joining lines ending with \
        i = 0
        while i < len(instructions) - 1:
            if instructions[i]["instruction"] == "LABEL" and instructions[i]["arguments"].endswith("\\"):
                instructions[i]["arguments"] = instructions[i]["arguments"][:-1] + " " + instructions[i+1]["arguments"]
                # Update the line number of the next instruction to point to the first line of the multiline instruction
                instructions[i+1]["line"] = instructions[i]["line"]
                del instructions[i+1]
            else:
                i += 1

        for instr in instructions:
            if instr["instruction"] == "LABEL":
                for key, value in self.parse_label_instruction(instr["arguments"]):
                    if key in self.url_labels and not self.is_valid_url(value):
                        errors.append({
                            "line": instr["line"],
                            "message": f"Label '{key}' has an invalid URL value: '{value}'.",
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

    def is_valid_url(self, url_string):
        """
        Checks if a string is a valid URL.

        Args:
            url_string (str): The string to check.

        Returns:
            bool: True if the string is a valid URL, False otherwise.
        """
        if not url_string:
            return True
        try:
            result = urlparse(url_string)
            return all([result.scheme, result.netloc])
        except ValueError:
            return False


@pytest.fixture
def label_value_is_url():
    return STX0047(url_labels=["website", "source"])


def test_label_value_is_url_detects_invalid_url(label_value_is_url):
    parsed_content = [
        {"line": 1, "instruction": "LABEL", "arguments": "maintainer='test' website='invalid_url'"},
    ]
    errors = label_value_is_url.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "Label 'website' has an invalid URL value" in errors[0]["message"]


def test_label_value_is_url_allows_valid_url(label_value_is_url):
    parsed_content = [
        {"line": 1, "instruction": "LABEL", "arguments": "website='https://example.com'"},
    ]
    errors = label_value_is_url.check(parsed_content)
    assert len(errors) == 0


def test_label_value_is_url_ignores_unspecified_labels(label_value_is_url):
    parsed_content = [
        {"line": 1, "instruction": "LABEL", "arguments": "version='not_a_url'"},
    ]
    errors = label_value_is_url.check(parsed_content)
    assert len(errors) == 0


def test_label_value_is_url_ignores_other_instructions(label_value_is_url):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "echo hello"},
    ]
    errors = label_value_is_url.check(parsed_content)
    assert len(errors) == 0


def test_label_value_is_url_detects_invalid_url_multiline(label_value_is_url):
    parsed_content = [
        {"line": 1, "instruction": "LABEL", "arguments": "maintainer='test' \\"},
        {"line": 2, "instruction": "SKIP", "arguments": "version='1.0' \\"},
        {"line": 3, "instruction": "SKIP", "arguments": "source='invalid_url'"},
    ]
    errors = label_value_is_url.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "Label 'source' has an invalid URL value" in errors[0]["message"]
