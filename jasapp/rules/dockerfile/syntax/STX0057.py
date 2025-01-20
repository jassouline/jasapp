import pytest
from jasapp.rules.base_rule import BaseRule


class STX0057(BaseRule):
    """
    Rule to ensure that `ln -s /bin/sh` is not used in `RUN` instructions to change the default shell.
    Instead, the `SHELL` instruction should be used.
    """
    rule_type = "dockerfile"

    def __init__(self):
        super().__init__(
            friendly_name="UseShellToChangeDefaultShell",
            hadolint="DL4005",
            name="STX0057",
            description="Use `SHELL` to change the default shell",
            severity="warning",
        )

    def check(self, instructions):
        """
        Checks if `ln -s /bin/sh` is used in `RUN` instructions to change the default shell.

        Args:
            instructions (list): A list of dictionaries containing parsed Dockerfile instructions.

        Returns:
            list: A list of errors found, each as a dictionary with line, message, and severity.
        """
        errors = []

        for instr in instructions:
            if instr["instruction"] == "RUN":
                if self.is_linking_bin_sh(instr["arguments"]):
                    errors.append({
                        "line": instr["line"],
                        "message": "Use `SHELL` to change the default shell, not `ln -s /bin/sh`",
                        "severity": self.severity,
                        "doc_link": f"https://github.com/jassouline/jasapp/wiki/{self.name}"
                    })

        return errors

    def is_linking_bin_sh(self, command_string):
        """
        Checks if a command string contains `ln -s /bin/sh`.

        Args:
            command_string (str): The command string to check.

        Returns:
            bool: True if `ln -s /bin/sh` is found, False otherwise.
        """

        return "ln" in command_string and "-s" in command_string and "/bin/sh" in command_string


@pytest.fixture
def use_shell_to_change_default_shell():
    return STX0057()


def test_ln_s_bin_sh_detects_invalid_command(use_shell_to_change_default_shell):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "ln -s /bin/sh /bin/bash"},
    ]
    errors = use_shell_to_change_default_shell.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "Use `SHELL` to change the default shell" in errors[0]["message"]


def test_ln_s_bin_sh_allows_other_ln_commands(use_shell_to_change_default_shell):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "ln -s /bin/foo /bin/bar"},
    ]
    errors = use_shell_to_change_default_shell.check(parsed_content)
    assert len(errors) == 0


def test_ln_s_bin_sh_allows_shell_instruction(use_shell_to_change_default_shell):
    parsed_content = [
        {"line": 1, "instruction": "SHELL", "arguments": '["/bin/bash", "-c"]'},
    ]
    errors = use_shell_to_change_default_shell.check(parsed_content)
    assert len(errors) == 0


def test_ln_s_bin_sh_ignores_other_instructions(use_shell_to_change_default_shell):
    parsed_content = [
        {"line": 1, "instruction": "ENV", "arguments": "MY_VAR=value"},
    ]
    errors = use_shell_to_change_default_shell.check(parsed_content)
    assert len(errors) == 0
