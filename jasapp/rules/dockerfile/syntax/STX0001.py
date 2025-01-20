import pytest
from jasapp.rules.base_rule import BaseRule


class STX0001(BaseRule):
    """
    Rule to ensure that the WORKDIR instruction uses an absolute path.
    """
    rule_type = "dockerfile"

    def __init__(self):
        super().__init__(
            friendly_name="UseAbsoluteWorkdir",
            hadolint="DL3000",
            name="STX0001",
            description="Ensure WORKDIR uses an absolute path.",
            severity="error",
        )

    @staticmethod
    def is_windows_absolute(path):
        """
        Check if a path is an absolute path in Windows format.

        Args:
            path (str): The path to check.

        Returns:
            bool: True if the path is absolute in Windows format, False otherwise.
        """
        return len(path) > 1 and path[1] == ":" and path[0].isalpha()

    def check(self, instructions):
        """
        Check if WORKDIR instructions use absolute paths.

        Args:
            instructions (list): A list of dictionaries containing parsed Dockerfile instructions.

        Returns:
            list: A list of errors found, each as a dictionary with line, message, and severity.
        """
        # Log all received instructions

        errors = []
        for instr in instructions:
            if instr["instruction"] == "WORKDIR":
                path = instr["arguments"].strip().strip('"').strip("'")

                if not (path.startswith("/") or self.is_windows_absolute(path)):
                    errors.append({
                        "line": instr["line"],
                        "message": "WORKDIR must use an absolute path (e.g., '/app' or 'C:\\\\path').",
                        "severity": self.severity,
                        "doc_link": f"https://github.com/jassouline/jasapp/wiki/{self.name}"
                    })

        return errors


# Pytest fixture for STX0001
@pytest.fixture
def use_absolute_workdir():
    return STX0001()


# Test cases for STX0001
def test_use_absolute_workdir_detects_relative_path(use_absolute_workdir):
    parsed_content = [{"line": 4, "instruction": "WORKDIR", "arguments": "app"}]
    errors = use_absolute_workdir.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["message"] == "WORKDIR must use an absolute path (e.g., '/app' or 'C:\\\\path')."


def test_use_absolute_workdir_detects_absolute_unix_path(use_absolute_workdir):
    parsed_content = [{"line": 5, "instruction": "WORKDIR", "arguments": "/app"}]
    errors = use_absolute_workdir.check(parsed_content)
    assert len(errors) == 0


def test_use_absolute_workdir_detects_absolute_windows_path(use_absolute_workdir):
    parsed_content = [{"line": 6, "instruction": "WORKDIR", "arguments": "C:\\\\app"}]
    errors = use_absolute_workdir.check(parsed_content)
    assert len(errors) == 0


def test_use_absolute_workdir_detects_env_variable_path(use_absolute_workdir):
    parsed_content = [{"line": 7, "instruction": "WORKDIR", "arguments": "$HOME"}]
    errors = use_absolute_workdir.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["message"] == "WORKDIR must use an absolute path (e.g., '/app' or 'C:\\\\path')."
