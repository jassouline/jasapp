import re
import pytest
from jasapp.rules.base_rule import BaseRule


class STX0045(BaseRule):
    """
    Rule to ensure that only allowed labels are used in LABEL instructions.
    """
    rule_type = "dockerfile"

    def __init__(self, allowed_labels=None, strict_labels=False):
        super().__init__(
            friendly_name="SuperfluousLabel",
            hadolint="DL3050",
            name="STX0045",
            description="Superfluous label present.",
            severity="info",
        )
        self.allowed_labels = set(allowed_labels) if allowed_labels else set()
        self.strict_labels = strict_labels

    def check(self, instructions):
        """
        Checks if only allowed labels are used in LABEL instructions.

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
                instructions[i]["arguments"] = instructions[i]["arguments"][:-1] + " " + instructions[i + 1]["arguments"]
                instructions[i]["line"] = instructions[i]["line"]  # Keep the line number of the first line
                del instructions[i + 1]  # Remove the merged instruction
            else:
                i += 1

        for instr in instructions:
            if instr["instruction"] == "LABEL":
                for key, value in self.parse_label_instruction(instr["arguments"]):
                    if self.strict_labels and key not in self.allowed_labels:
                        errors.append({
                            "line": instr["line"],
                            "message": f"Superfluous label: '{key}'.",
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
def superfluous_label_strict():
    return STX0045(allowed_labels=["maintainer", "version"], strict_labels=True)


@pytest.fixture
def superfluous_label_non_strict():
    return STX0045(allowed_labels=["maintainer", "version"], strict_labels=False)


def test_superfluous_label_detects_unallowed_label_strict(superfluous_label_strict):
    parsed_content = [
        {"line": 1, "instruction": "LABEL", "arguments": "maintainer='test' version='1.0' extra='label'"},
    ]
    errors = superfluous_label_strict.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "Superfluous label: 'extra'" in errors[0]["message"]


def test_superfluous_label_allows_allowed_labels_strict(superfluous_label_strict):
    parsed_content = [
        {"line": 1, "instruction": "LABEL", "arguments": "maintainer='test' version='1.0'"},
    ]
    errors = superfluous_label_strict.check(parsed_content)
    assert len(errors) == 0


def test_superfluous_label_ignores_unallowed_label_non_strict(superfluous_label_non_strict):
    parsed_content = [
        {"line": 1, "instruction": "LABEL", "arguments": "maintainer='test' version='1.0' extra='label'"},
    ]
    errors = superfluous_label_non_strict.check(parsed_content)
    assert len(errors) == 0


def test_superfluous_label_ignores_other_instructions(superfluous_label_strict):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "echo hello"},
    ]
    errors = superfluous_label_strict.check(parsed_content)
    assert len(errors) == 0


def test_superfluous_label_detects_multiline_unallowed_label_strict(superfluous_label_strict):
    parsed_content = [
        {"line": 1, "instruction": "LABEL", "arguments": "maintainer='test' \\"},
        {"line": 2, "instruction": "LABEL", "arguments": "version='1.0' \\"},
        {"line": 3, "instruction": "LABEL", "arguments": "extra='label'"},
    ]
    errors = superfluous_label_strict.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "Superfluous label: 'extra'" in errors[0]["message"]
