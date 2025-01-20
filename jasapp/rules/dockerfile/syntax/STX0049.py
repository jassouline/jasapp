import re
import pytest
from jasapp.rules.base_rule import BaseRule


class STX0049(BaseRule):
    """
    Rule to ensure that label values, for specific required labels, are valid SPDX license identifiers.
    """
    rule_type = "dockerfile"

    def __init__(self, spdx_labels=None):
        super().__init__(
            friendly_name="LabelValueIsSPDX",
            hadolint="DL3054",
            name="STX0049",
            description="Label value is not a valid SPDX identifier.",
            severity="warning",
        )
        self.spdx_labels = set(spdx_labels) if spdx_labels else set()

    def check(self, instructions):
        """
        Checks if label values, for specific required labels, are valid SPDX license identifiers.

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

                # Correctly identify the end of multi-line LABEL instructions
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
                    if key in self.spdx_labels and not self.is_valid_spdx_license(value):
                        errors.append({
                            "line": instr["line"],
                            "message": f"Label '{key}' has an invalid SPDX license identifier value: '{value}'.",
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

    def is_valid_spdx_license(self, license_string):
        """
        Checks if a string is a valid SPDX license identifier based on a simple format check.

        Args:
            license_string (str): The string to check.

        Returns:
            bool: True if the string is a potentially valid SPDX license identifier, False otherwise.
        """
        if not license_string:
            return True

        # Basic SPDX format check:
        # - Alphanumeric characters, dashes, dots and plus signs are allowed
        # - At least one character
        return bool(re.fullmatch(r"^[a-zA-Z0-9\-\+\.]+$", license_string))


@pytest.fixture
def label_value_is_spdx():
    return STX0049(spdx_labels=["license"])


def test_label_value_is_spdx_detects_invalid_license(label_value_is_spdx):
    parsed_content = [
        {"line": 1, "instruction": "LABEL", "arguments": "maintainer='test' license='invalid_license'"},
    ]
    errors = label_value_is_spdx.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "Label 'license' has an invalid SPDX license identifier" in errors[0]["message"]


def test_label_value_is_spdx_allows_valid_license(label_value_is_spdx):
    parsed_content = [
        {"line": 1, "instruction": "LABEL", "arguments": "license='MIT'"},
    ]
    errors = label_value_is_spdx.check(parsed_content)
    assert len(errors) == 0


def test_label_value_is_spdx_ignores_unspecified_labels(label_value_is_spdx):
    parsed_content = [
        {"line": 1, "instruction": "LABEL", "arguments": "version='not_a_license'"},
    ]
    errors = label_value_is_spdx.check(parsed_content)
    assert len(errors) == 0


def test_label_value_is_spdx_ignores_other_instructions(label_value_is_spdx):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "echo hello"},
    ]
    errors = label_value_is_spdx.check(parsed_content)
    assert len(errors) == 0


# def test_label_value_is_spdx_detects_invalid_license_multiline(label_value_is_spdx):
#    parsed_content = [
#        {"line": 1, "instruction": "LABEL", "arguments": "maintainer='test' \\"},
#        {"line": 2, "instruction": "SKIP_THIS", "arguments": "license='Invalid License' \\"},
#        {"line": 3, "instruction": "SKIP_THIS", "arguments": "source='https://example.com'"},
#    ]
#    errors = label_value_is_spdx.check(parsed_content)
#    assert len(errors) == 1
#    assert errors[0]["line"] == 1
#    assert "Label 'license' has an invalid SPDX license identifier" in errors[0]["message"]
