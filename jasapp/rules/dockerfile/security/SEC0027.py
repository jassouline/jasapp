import pytest
from jasapp.rules.base_rule import BaseRule


class SEC0027(BaseRule):
    """
    Rule to detect if the `--trusted-host` option is used with `pip` in `RUN` instructions.
    """
    rule_type = "dockerfile"

    def __init__(self):
        super().__init__(
            friendly_name="PipTrustedHostUsed",
            name="SEC0027",
            description="`pip` command in `RUN` instruction is using `--trusted-host` option.",
            severity="warning",  # Changed severity to warning
        )

    def check(self, instructions):
        """
        Checks if `pip` commands in `RUN` instructions are using `--trusted-host`.

        Args:
            instructions (list): A list of dictionaries containing parsed Dockerfile instructions.

        Returns:
            list: A list of errors found, each as a dictionary with line, message, and severity.
        """
        errors = []

        for instr in instructions:
            if instr["instruction"] == "RUN":
                if self.is_pip_using_trusted_host(instr["arguments"]):
                    errors.append({
                        "line": instr["line"],
                        "message": "`pip` command in `RUN` instruction is using `--trusted-host` option. "
                                   "Review if the trusted hosts are legitimate and necessary.",
                        "severity": self.severity,
                        "doc_link": f"https://github.com/jassouline/jasapp/wiki/{self.name}"
                    })

        return errors

    def is_pip_using_trusted_host(self, command_string):
        """
        Checks if a command string contains a `pip` command that uses the `--trusted-host` option.

        Args:
            command_string (str): The command string to check.

        Returns:
            bool: True if `pip` is used with `--trusted-host`, False otherwise.
        """
        if "pip" not in command_string:
            return False

        # Check for --trusted-host flag
        return "--trusted-host" in command_string


@pytest.fixture
def pip_trusted_host_used():
    return SEC0027()


def test_pip_trusted_host_detects_trusted_host(pip_trusted_host_used):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "pip install --trusted-host pypi.org --index-url https://pypi.org/simple/ requests"},
    ]
    errors = pip_trusted_host_used.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "`pip` command in `RUN` instruction is using `--trusted-host` option" in errors[0]["message"]


def test_pip_trusted_host_allows_secure_pip(pip_trusted_host_used):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "pip install requests"},
    ]
    errors = pip_trusted_host_used.check(parsed_content)
    assert len(errors) == 0


def test_pip_trusted_host_ignores_other_instructions(pip_trusted_host_used):
    parsed_content = [
        {"line": 1, "instruction": "ENV", "arguments": "MY_VAR=value"},
    ]
    errors = pip_trusted_host_used.check(parsed_content)
    assert len(errors) == 0
