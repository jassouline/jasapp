import re
import pytest
from jasapp.rules.base_rule import BaseRule


class STX0044(BaseRule):
    """
    Rule to ensure that required labels are defined in each stage of a Dockerfile.
    """
    rule_type = "dockerfile"

    def __init__(self, required_labels=[]):
        super().__init__(
            friendly_name="MissingRequiredLabel",
            hadolint="DL3049",
            name="STX0044",
            description="Required label is missing.",
            severity="info",
        )
        self.required_labels = required_labels

    def check(self, instructions):
        """
        Checks if required labels are defined in each stage of a Dockerfile.

        Args:
            instructions (list): A list of dictionaries containing parsed Dockerfile instructions.

        Returns:
            list: A list of errors found, each as a dictionary with line, message, and severity.
        """
        errors = []
        current_stage = None
        current_stage_labels = {}
        stage_labels = {}  # Initialize stage_labels here

        # Handle multi-line instructions by joining lines ending with \
        for i in range(len(instructions) - 1):
            if instructions[i]["instruction"] == "LABEL" and instructions[i]["arguments"].endswith("\\"):
                instructions[i]["arguments"] = instructions[i]["arguments"][:-1] + instructions[i+1]["arguments"]
                instructions[i+1]["instruction"] = "SKIP"

        for instr in instructions:
            if instr["instruction"] == "SKIP":
                continue
            elif instr["instruction"] == "FROM":
                # Save labels for the previous stage if it exists
                if current_stage is not None:
                    stage_labels[current_stage] = current_stage_labels

                # New stage
                current_stage = instr["arguments"].split(" as ")[-1].split(" AS ")[-1] if " as " in instr["arguments"].lower() else instr["arguments"]
                current_stage_labels = {}

            elif instr["instruction"] == "LABEL":
                if current_stage is not None:
                    # Store labels for the current stage
                    labels = self.parse_label_instruction(instr["arguments"])

                    for key, value in labels:
                        current_stage_labels[key] = value

            elif instr["instruction"] == "ONBUILD" and "MAINTAINER" in instr["arguments"]:
                # Ignore deprecated ONBUILD MAINTAINER instruction
                continue

        # Save labels for the last stage if it exists
        if current_stage is not None:
            stage_labels[current_stage] = current_stage_labels

        # Check for missing required labels in each stage
        for stage, labels in stage_labels.items():
            for required_label in self.required_labels:
                if required_label not in labels:
                    errors.append({
                        "line": 1,  # You may need to adjust this based on your parsing logic
                        "message": f"Stage '{stage}' is missing required label '{required_label}'.",
                        "severity": self.severity,
                        "doc_link": f"https://github.com/jassouline/jasapp/wiki/{self.name}"
                    })

        return errors

    def parse_label_instruction(self, arguments):
        pairs = []

        # Remove any trailing comments from the arguments string
        arguments = arguments.split("#")[0].strip()

        # Use regular expression to split arguments, handling quoted values
        parts = re.split(r'\s(?=(?:[^"\']*["\'][^"\']*["\'])*[^"\']*$)', arguments)

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


@pytest.fixture
def missing_required_label():
    return STX0044(required_labels=["maintainer", "version"])


def test_missing_required_label_detects_missing_labels(missing_required_label):
    parsed_content = [
        {"line": 1, "instruction": "FROM", "arguments": "ubuntu:latest"},
        {"line": 2, "instruction": "LABEL", "arguments": "maintainer='test'"},
        {"line": 3, "instruction": "FROM", "arguments": "alpine:latest AS builder"},
        {"line": 4, "instruction": "LABEL", "arguments": "version='1.0'"},
    ]
    errors = missing_required_label.check(parsed_content)
    assert len(errors) == 2
    assert errors[0]["line"] == 1
    assert "Stage 'ubuntu:latest'" in errors[0]["message"]
    assert "version" in errors[0]["message"]
    assert errors[1]["line"] == 1
    assert "Stage 'builder'" in errors[1]["message"]
    assert "maintainer" in errors[1]["message"]


def test_missing_required_label_allows_required_labels(missing_required_label):
    parsed_content = [
        {"line": 1, "instruction": "FROM", "arguments": "ubuntu:latest"},
        {"line": 2, "instruction": "LABEL", "arguments": "maintainer='test' version='1.0'"},
    ]
    errors = missing_required_label.check(parsed_content)
    assert len(errors) == 0


def test_missing_required_label_allows_required_labels_multiline(missing_required_label):
    parsed_content = [
        {"line": 1, "instruction": "FROM", "arguments": "ubuntu:latest"},
        {"line": 2, "instruction": "LABEL", "arguments": "maintainer='test' \\"},
        {"line": 3, "instruction": "SKIP", "arguments": "version='1.0'"},
    ]
    errors = missing_required_label.check(parsed_content)
    assert len(errors) == 0


def test_missing_required_label_allows_required_labels_multilabel(missing_required_label):
    parsed_content = [
        {"line": 1, "instruction": "FROM", "arguments": "ubuntu:latest"},
        {"line": 2, "instruction": "LABEL", "arguments": "maintainer='test'"},
        {"line": 3, "instruction": "LABEL", "arguments": "version='1.0'"},
    ]
    errors = missing_required_label.check(parsed_content)
    assert len(errors) == 0


def test_missing_required_label_ignores_onbuild_maintainer(missing_required_label):
    parsed_content = [
        {"line": 1, "instruction": "FROM", "arguments": "ubuntu:latest"},
        {"line": 2, "instruction": "ONBUILD", "arguments": "MAINTAINER test"},
        {"line": 3, "instruction": "LABEL", "arguments": "version='1.0'"},
    ]
    errors = missing_required_label.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "Stage 'ubuntu:latest'" in errors[0]["message"]
    assert "maintainer" in errors[0]["message"]
