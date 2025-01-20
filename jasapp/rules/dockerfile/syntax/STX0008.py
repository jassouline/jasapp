import pytest
from jasapp.rules.base_rule import BaseRule


class STX0008(BaseRule):
    """
    Rule to ensure that apt/apt-get lists are deleted after installing packages.
    """
    rule_type = "dockerfile"

    def __init__(self):
        super().__init__(
            friendly_name="DeleteAptLists",
            hadolint="DL3009",
            name="STX0008",
            description="Ensure that `apt` or `apt-get` lists are deleted after installing packages to reduce image size.",
            severity="info",
        )

    def check(self, instructions):
        """
        Check if apt/apt-get lists are deleted after installing packages.

        Args:
            instructions (list): A list of dictionaries containing parsed Dockerfile instructions.

        Returns:
            list: A list of errors found, each as a dictionary with line, message, and severity.
        """
        errors = []
        pending_cleanup = False
        last_install_line = None

        for instr in instructions:
            if instr["instruction"] == "RUN":
                commands = [cmd.strip() for cmd in instr["arguments"].split("&&")]

                # Detect apt or apt-get commands
                if any(cmd.startswith(("apt update", "apt-get update", "apt install", "apt-get install")) for cmd in commands):
                    pending_cleanup = True
                    last_install_line = instr["line"]

                # Detect cleanup command
                if any("rm -rf /var/lib/apt/lists/*" in cmd for cmd in commands):
                    pending_cleanup = False
                    last_install_line = None

        # If pending cleanup remains at the end, add an error
        if pending_cleanup and last_install_line is not None:
            errors.append({
                "line": last_install_line,
                "message": "Delete the apt-get lists after installing something (e.g., `rm -rf /var/lib/apt/lists/*`).",
                "severity": self.severity,
                "doc_link": f"https://github.com/jassouline/jasapp/wiki/{self.name}"
            })

        return errors


# Pytest fixture for STX0008
@pytest.fixture
def delete_apt_lists():
    return STX0008()


# Tests for STX0008
def test_delete_apt_lists_detects_missing_cleanup(delete_apt_lists):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "apt-get update && apt-get install -y curl"},
    ]
    errors = delete_apt_lists.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert errors[0]["message"] == "Delete the apt-get lists after installing something (e.g., `rm -rf /var/lib/apt/lists/*`)."


def test_delete_apt_lists_handles_multiple_commands(delete_apt_lists):
    parsed_content = [
        {"line": 4, "instruction": "RUN", "arguments": "apt-get update && apt-get install -y curl && apt-get install -y nano"},
        {"line": 5, "instruction": "RUN", "arguments": "rm -rf /var/lib/apt/lists/*"},
    ]
    errors = delete_apt_lists.check(parsed_content)
    assert len(errors) == 0


def test_delete_apt_lists_detects_missing_cleanup_across_lines(delete_apt_lists):
    parsed_content = [
        {"line": 6, "instruction": "RUN", "arguments": "apt update && apt install -y curl"},
        {"line": 7, "instruction": "RUN", "arguments": "echo 'No cleanup here'"},
    ]
    errors = delete_apt_lists.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 6
    assert errors[0]["message"] == "Delete the apt-get lists after installing something (e.g., `rm -rf /var/lib/apt/lists/*`)."


def test_delete_apt_lists_allows_proper_cleanup(delete_apt_lists):
    parsed_content = [
        {"line": 8, "instruction": "RUN", "arguments": "apt update && apt install -y curl && rm -rf /var/lib/apt/lists/*"},
    ]
    errors = delete_apt_lists.check(parsed_content)
    assert len(errors) == 0


def test_delete_apt_lists_allows_combined_cleanup(delete_apt_lists):
    parsed_content = [
        {"line": 9, "instruction": "RUN", "arguments": "apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*"},
    ]
    errors = delete_apt_lists.check(parsed_content)
    assert len(errors) == 0


def test_delete_apt_lists_ignores_non_apt_commands(delete_apt_lists):
    parsed_content = [
        {"line": 10, "instruction": "RUN", "arguments": "yum install -y curl"},
    ]
    errors = delete_apt_lists.check(parsed_content)
    assert len(errors) == 0
