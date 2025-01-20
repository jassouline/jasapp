import pytest
from jasapp.rules.base_rule import BaseRule


class STX0014(BaseRule):
    """
    Rule to ensure the `-y` switch is used with `apt-get install` to avoid manual input.
    """
    rule_type = "dockerfile"

    def __init__(self):
        super().__init__(
            friendly_name="UseAptYesOption",
            hadolint="DL3014",
            name="STX0014",
            description="Use the `-y` switch to avoid manual input in `apt-get install <package>`.",
            severity="warning",
        )

    def check(self, instructions):
        """
        Checks if `apt-get install` commands use the `-y` switch.

        Args:
            instructions (list): A list of dictionaries containing parsed Dockerfile instructions.

        Returns:
            list: A list of errors found, each as a dictionary with line, message, and severity.
        """
        errors = []
        for instr in instructions:
            if instr["instruction"] == "RUN":
                commands = instr["arguments"].split("&&")
                for command in commands:
                    command = command.strip()
                    if self.is_apt_get_install(command) and not self.has_yes_option(command):
                        errors.append({
                            "line": instr["line"],
                            "message": (
                                "Use the `-y` switch to avoid manual input in `apt-get install <package>`."
                            ),
                            "severity": self.severity,
                            "doc_link": f"https://github.com/jassouline/jasapp/wiki/{self.name}"
                        })
        return errors

    @staticmethod
    def is_apt_get_install(command):
        """
        Check if a command is an `apt-get install` command.

        Args:
            command (str): The command to check.

        Returns:
            bool: True if the command is an `apt-get install` command, False otherwise.
        """
        return "apt-get install" in command

    @staticmethod
    def has_yes_option(command):
        """
        Check if an `apt-get install` command includes the `-y` switch or equivalent.

        Args:
            command (str): The `apt-get install` command to check.

        Returns:
            bool: True if the `-y` switch or equivalent is present, False otherwise.
        """
        flags = {"-y", "--yes", "-qq", "--assume-yes", "-q=2", "--quiet=2"}
        command_parts = command.split()
        for part in command_parts:
            if part in flags or part.startswith("-q") and part.count("q") == 2:
                return True
        return False


@pytest.fixture
def use_apt_yes_option():
    return STX0014()


def test_use_apt_yes_option_detects_missing_yes_option(use_apt_yes_option):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "apt-get install curl"},
    ]
    errors = use_apt_yes_option.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert errors[0]["message"] == "Use the `-y` switch to avoid manual input in `apt-get install <package>`."


def test_use_apt_yes_option_allows_yes_option(use_apt_yes_option):
    parsed_content = [
        {"line": 2, "instruction": "RUN", "arguments": "apt-get install -y curl"},
        {"line": 3, "instruction": "RUN", "arguments": "apt-get install --yes vim"},
    ]
    errors = use_apt_yes_option.check(parsed_content)
    assert len(errors) == 0


def test_use_apt_yes_option_allows_quiet_flags(use_apt_yes_option):
    parsed_content = [
        {"line": 4, "instruction": "RUN", "arguments": "apt-get install -qq curl"},
        {"line": 5, "instruction": "RUN", "arguments": "apt-get install --quiet=2 vim"},
    ]
    errors = use_apt_yes_option.check(parsed_content)
    assert len(errors) == 0


def test_use_apt_yes_option_handles_multiple_commands(use_apt_yes_option):
    parsed_content = [
        {"line": 6, "instruction": "RUN", "arguments": "apt-get update && apt-get install curl && apt-get install vim -y"},
    ]
    errors = use_apt_yes_option.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 6
    assert errors[0]["message"] == "Use the `-y` switch to avoid manual input in `apt-get install <package>`."


def test_use_apt_yes_option_allows_already_silent_command(use_apt_yes_option):
    parsed_content = [
        {"line": 7, "instruction": "RUN", "arguments": "apt-get install --assume-yes curl"},
    ]
    errors = use_apt_yes_option.check(parsed_content)
    assert len(errors) == 0
