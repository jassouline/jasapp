import re
import pytest
from email_validator import validate_email, EmailNotValidError
from jasapp.rules.base_rule import BaseRule


class STX0051(BaseRule):
    """
    Rule to ensure that label values, for specific required labels, are valid email addresses.
    """
    rule_type = "dockerfile"

    def __init__(self, email_labels=None):
        super().__init__(
            friendly_name="LabelValueIsEmail",
            hadolint="DL3058",
            name="STX0051",
            description="Label value is not a valid email address.",
            severity="warning",
        )
        self.email_labels = set(email_labels) if email_labels else set()

    def check(self, instructions):
        """
        Checks if label values, for specific required labels, are valid email addresses.

        Args:
            instructions (list): A list of dictionaries containing parsed Dockerfile instructions.

        Returns:
            list: A list of errors found, each as a dictionary with line, message, and severity.
        """
        errors = []

        # Handle multi-line instructions by joining lines ending with \
        modified_instructions = []
        i = 0
        while i < len(instructions):
            if instructions[i]["instruction"] == "LABEL" and instructions[i]["arguments"].endswith("\\"):
                j = i + 1
                multiline_args = [instructions[i]["arguments"][:-1].strip()]
                while j < len(instructions) and instructions[j]["instruction"] == "SKIP_THIS" and instructions[j]["arguments"].endswith("\\"):
                    multiline_args.append(instructions[j]["arguments"][:-1].strip())
                    j += 1
                if j < len(instructions) and instructions[j]["instruction"] == "SKIP_THIS":
                    multiline_args.append(instructions[j]["arguments"].strip())
                    j += 1
                # Create a new instruction with merged arguments and the original line number
                modified_instructions.append({
                    "line": instructions[i]["line"],
                    "instruction": "LABEL",
                    "arguments": " ".join(multiline_args)
                })
                i = j  # Skip the lines that were merged
            else:
                modified_instructions.append(instructions[i])
                i += 1

        for instr in modified_instructions:
            if instr["instruction"] == "LABEL":
                for key, value in self.parse_label_instruction(instr["arguments"]):
                    if key in self.email_labels and not self.is_valid_email(value):
                        errors.append({
                            "line": instr["line"],
                            "message": f"Label '{key}' has an invalid email address value: '{value}'.",
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

    def is_valid_email(self, email_string):
        """
        Checks if a string is a valid email address using the email_validator library.

        Args:
            email_string (str): The string to check.

        Returns:
            bool: True if the string is a valid email, False otherwise.
        """
        if not email_string:
            return True
        try:
            validate_email(email_string, check_deliverability=False)
            return True
        except EmailNotValidError:
            return False


@pytest.fixture
def label_value_is_email():
    return STX0051(email_labels=["maintainer"])


def test_label_value_is_email_detects_invalid_email(label_value_is_email):
    parsed_content = [
        {"line": 1, "instruction": "LABEL", "arguments": "maintainer='invalid_email' version='1.0'"},
    ]
    errors = label_value_is_email.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "Label 'maintainer' has an invalid email address value" in errors[0]["message"]


def test_label_value_is_email_allows_valid_email(label_value_is_email):
    parsed_content = [
        {"line": 1, "instruction": "LABEL", "arguments": "maintainer='test@example.com'"},
    ]
    errors = label_value_is_email.check(parsed_content)
    assert len(errors) == 0


def test_label_value_is_email_ignores_unspecified_labels(label_value_is_email):
    parsed_content = [
        {"line": 1, "instruction": "LABEL", "arguments": "website='invalid_email'"},
    ]
    errors = label_value_is_email.check(parsed_content)
    assert len(errors) == 0


def test_label_value_is_email_ignores_other_instructions(label_value_is_email):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "echo hello"},
    ]
    errors = label_value_is_email.check(parsed_content)
    assert len(errors) == 0


def test_label_value_is_email_detects_invalid_email_multiline(label_value_is_email):
    parsed_content = [
        {"line": 1, "instruction": "LABEL", "arguments": "version='1.0' \\"},
        {"line": 2, "instruction": "SKIP_THIS", "arguments": "maintainer='invalid_email'"},
    ]
    errors = label_value_is_email.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "Label 'maintainer' has an invalid email address value" in errors[0]["message"]
