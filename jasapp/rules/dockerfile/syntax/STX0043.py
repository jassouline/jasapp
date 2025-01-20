import re
import pytest
from jasapp.rules.base_rule import BaseRule


class STX0043(BaseRule):
    """
    Rule to ensure that label keys are valid according to Dockerfile label conventions.
    """
    rule_type = "dockerfile"

    def __init__(self):
        super().__init__(
            friendly_name="ValidLabelKey",
            hadolint="DL3048",
            name="STX0043",
            description="Invalid label key.",
            severity="info",
        )

    def check(self, instructions):
        """
        Checks if label keys in LABEL instructions are valid.

        Args:
            instructions (list): A list of dictionaries containing parsed Dockerfile instructions.

        Returns:
            list: A list of errors found, each as a dictionary with line, message, and severity.
        """
        errors = []

        for instr in instructions:
            if instr["instruction"] == "LABEL":
                for key, value in self.parse_label_instruction(instr["arguments"]):
                    if not self.is_valid_label_key(key):
                        errors.append({
                            "line": instr["line"],
                            "message": f"Invalid label key: '{key}'.",
                            "severity": self.severity,
                            "doc_link": f"https://github.com/jassouline/jasapp/wiki/{self.name}"
                        })

        return errors

    def parse_label_instruction(self, arguments):
        pairs = []

        # Remove any trailing comments from the arguments string
        arguments = arguments.split("#")[0].strip()

        # Handle multi-line LABEL instructions by joining lines ending with \
        arguments = arguments.replace("\\\n", " ").replace("\\\r\n", " ")

        # Use regular expression to split arguments, handling quoted values
        parts = re.split(r'\s(?=(?:[^"\']*["\'][^"\']*["\'])*[^"\']*$)', arguments)

        current_key = None
        current_value = ""

        for part in parts:
            if "=" in part:
                key, value = part.split("=", 1)

                # Remove quotes from key and value if present
                key = key.strip().strip('"').strip("'")
                value = value.strip().strip('"').strip("'")

                if current_key is not None:
                    pairs.append((current_key, current_value))

                current_key = key
                current_value = value

            elif current_key is not None:
                current_value += " " + part.strip() if current_value else part.strip()
            else:
                current_key = part.strip()

        if current_key is not None:
            pairs.append((current_key, current_value))

        return pairs

    def is_valid_label_key(self, key):
        """
        Checks if a label key is valid according to the rules:
        1. Must start with a lowercase letter.
        2. Must end with a lowercase letter or digit.
        3. Can only contain lowercase letters, digits, '.', and '-'.
        4. Cannot have consecutive '.' or '-'.
        5. Cannot use reserved namespaces (com.docker.*, io.docker.*, org.dockerproject.*).

        Args:
            key (str): The label key to check.

        Returns:
            bool: True if the label key is valid, False otherwise.
        """
        if not key:
            return True
        if not key[0].islower():
            return False
        if not (key[-1].islower() or key[-1].isdigit()):
            return False
        if not all(c.islower() or c.isdigit() or c in ['.', '-'] for c in key):
            return False
        if ".." in key or "--" in key:
            return False
        if key.startswith("com.docker.") or key.startswith("io.docker.") or key.startswith("org.dockerproject."):
            return False
        return True


@pytest.fixture
def valid_label_key():
    return STX0043()


def test_invalid_label_key_start(valid_label_key):
    parsed_content = [
        {"line": 1, "instruction": "LABEL", "arguments": "1Key=value"},
    ]
    errors = valid_label_key.check(parsed_content)
    assert len(errors) == 1
    assert "Invalid label key: '1Key'" in errors[0]["message"]


def test_invalid_label_key_end(valid_label_key):
    parsed_content = [
        {"line": 1, "instruction": "LABEL", "arguments": "a-key=value"},
    ]
    errors = valid_label_key.check(parsed_content)
    assert len(errors) == 0


def test_invalid_label_key_char(valid_label_key):
    parsed_content = [
        {"line": 1, "instruction": "LABEL", "arguments": "a_key=value"},
    ]
    errors = valid_label_key.check(parsed_content)
    assert len(errors) == 1
    assert "Invalid label key: 'a_key'" in errors[0]["message"]


def test_invalid_label_key_consecutive_separators(valid_label_key):
    parsed_content = [
        {"line": 1, "instruction": "LABEL", "arguments": "a--key=value"},
    ]
    errors = valid_label_key.check(parsed_content)
    assert len(errors) == 1
    assert "Invalid label key: 'a--key'" in errors[0]["message"]


def test_invalid_label_key_reserved_namespace(valid_label_key):
    parsed_content = [
        {"line": 1, "instruction": "LABEL", "arguments": "com.docker.key=value"},
    ]
    errors = valid_label_key.check(parsed_content)
    assert len(errors) == 1
    assert "Invalid label key: 'com.docker.key'" in errors[0]["message"]


def test_valid_label_key(valid_label_key):
    parsed_content = [
        {"line": 1, "instruction": "LABEL", "arguments": "a.valid-key=value"},
    ]
    errors = valid_label_key.check(parsed_content)
    assert len(errors) == 0


def test_multiline_label(valid_label_key):
    parsed_content = [
        {"line": 1, "instruction": "LABEL", "arguments": "key1=value1 \\"},
        {"line": 2, "instruction": "", "arguments": "      key2=value2"},
    ]
    errors = valid_label_key.check(parsed_content)
    assert len(errors) == 0


def test_quoted_label_values(valid_label_key):
    parsed_content = [
        {"line": 1, "instruction": "LABEL", "arguments": "key1='value with spaces' \"key2\"=value2 key3=\"value with spaces\""},
    ]
    errors = valid_label_key.check(parsed_content)
    assert len(errors) == 0


def test_label_with_no_value(valid_label_key):
    parsed_content = [
        {"line": 1, "instruction": "LABEL", "arguments": "key1 key2=value2"},
    ]
    errors = valid_label_key.check(parsed_content)
    assert len(errors) == 0


def test_multiline_label_with_comments(valid_label_key):
    parsed_content = [
        {"line": 1, "instruction": "LABEL", "arguments": "key1=value1 \\ # comment"},
        {"line": 2, "instruction": "", "arguments": "      key2=value2"},
    ]
    errors = valid_label_key.check(parsed_content)
    assert len(errors) == 0


def test_empty_label_key(valid_label_key):
    parsed_content = [
        {"line": 1, "instruction": "LABEL", "arguments": ""},
    ]
    errors = valid_label_key.check(parsed_content)
    assert len(errors) == 0
