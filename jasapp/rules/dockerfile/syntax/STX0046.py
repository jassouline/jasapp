import re
import pytest
from jasapp.rules.base_rule import BaseRule


class STX0046(BaseRule):
    """
    Rule to ensure that specified labels in LABEL instructions are not empty.
    """
    rule_type = "dockerfile"

    def __init__(self, required_labels=None):
        super().__init__(
            friendly_name="LabelNotEmpty",
            hadolint="DL3051",
            name="STX0046",
            description="Label is empty.",
            severity="warning",
        )
        self.required_labels = set(required_labels) if required_labels else set()

    def check(self, instructions):
        """
        Checks if specified labels in LABEL instructions are not empty.

        Args:
            instructions (list): A list of dictionaries containing parsed Dockerfile instructions.

        Returns:
            list: A list of errors found, each as a dictionary with line, message, and severity.
        """
        errors = []

        for instr in instructions:
            if instr["instruction"] == "LABEL":
                for key, value in self.parse_label_instruction(instr["arguments"]):
                    if key in self.required_labels and not value:
                        errors.append({
                            "line": instr["line"],
                            "message": f"Label '{key}' is empty.",
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

        # Handle multi-line LABEL instructions by joining lines ending with \
        arguments = arguments.replace("\\\n", " ").replace("\\\r\n", " ")

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
                key = part.strip().strip('"').strip("'")
                pairs.append((key, ""))  # Assign an empty string as the value

        return pairs


@pytest.fixture
def label_not_empty():
    return STX0046(required_labels=["maintainer", "version"])


def test_label_not_empty_detects_empty_label(label_not_empty):
    parsed_content = [
        {"line": 1, "instruction": "LABEL", "arguments": "maintainer='' version='1.0'"},
    ]
    errors = label_not_empty.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "Label 'maintainer' is empty." in errors[0]["message"]


def test_label_not_empty_allows_non_empty_label(label_not_empty):
    parsed_content = [
        {"line": 1, "instruction": "LABEL", "arguments": "maintainer='test' version='1.0'"},
    ]
    errors = label_not_empty.check(parsed_content)
    assert len(errors) == 0


def test_label_not_empty_ignores_other_labels(label_not_empty):
    parsed_content = [
        {"line": 1, "instruction": "LABEL", "arguments": "description='' version='1.0'"},
    ]
    errors = label_not_empty.check(parsed_content)
    assert len(errors) == 0


def test_label_not_empty_ignores_other_instructions(label_not_empty):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "echo hello"},
    ]
    errors = label_not_empty.check(parsed_content)
    assert len(errors) == 0


def test_label_not_empty_handles_multiline_label(label_not_empty):
    parsed_content = [
        {"line": 1, "instruction": "LABEL", "arguments": "maintainer='' \\"},
        {"line": 2, "instruction": "SKIP", "arguments": "version='1.0'"},
    ]
    errors = label_not_empty.check(parsed_content)
    assert len(errors) == 1
    assert "Label 'maintainer' is empty." in errors[0]["message"]


def test_label_not_empty_handles_quoted_values(label_not_empty):
    parsed_content = [
        {"line": 1, "instruction": "LABEL", "arguments": "maintainer=\"\" version='1.0'"},
    ]
    errors = label_not_empty.check(parsed_content)
    assert len(errors) == 1
    assert "Label 'maintainer' is empty." in errors[0]["message"]


def test_label_not_empty_handles_unversioned_label(label_not_empty):
    parsed_content = [
        {"line": 1, "instruction": "LABEL", "arguments": "maintainer version"},
    ]
    errors = label_not_empty.check(parsed_content)
    assert len(errors) == 2
    assert "Label 'maintainer' is empty." in errors[0]["message"]
    assert "Label 'version' is empty." in errors[1]["message"]
