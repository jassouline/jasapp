import pytest
from jasapp.rules.base_rule import BaseRule


class SEC0019(BaseRule):
    """
    Rule to detect if the `apt` or `apt-get` package manager is configured to allow unauthenticated packages.
    """
    rule_type = "dockerfile"

    def __init__(self):
        super().__init__(
            friendly_name="AptUnauthenticatedPackages",
            name="SEC0019",
            description="`apt` or `apt-get` is configured to allow unauthenticated packages.",
            severity="error",
        )

    def check(self, instructions):
        """
        Checks if `apt` or `apt-get` commands in `RUN` instructions allow unauthenticated packages.

        Args:
            instructions (list): A list of dictionaries containing parsed Dockerfile instructions.

        Returns:
            list: A list of errors found, each as a dictionary with line, message, and severity.
        """
        errors = []

        for instr in instructions:
            if instr["instruction"] == "RUN":
                if self.is_apt_allowing_unauthenticated(instr["arguments"]):
                    errors.append({
                        "line": instr["line"],
                        "message": "`apt` or `apt-get` is configured to allow unauthenticated packages. "
                                   "Use `--allow-unauthenticated` only if necessary and with caution.",
                        "severity": self.severity,
                        "doc_link": f"https://github.com/jassouline/jasapp/wiki/{self.name}"
                    })

        return errors

    def is_apt_allowing_unauthenticated(self, command_string):
        """
        Checks if a command string contains an `apt` or `apt-get` command that allows unauthenticated packages.

        Args:
            command_string (str): The command string to check.

        Returns:
            bool: True if `apt` or `apt-get` allows unauthenticated packages, False otherwise.
        """
        if not ("apt-get" in command_string or "apt " in command_string):
            return False

        # Check for --allow-unauthenticated flag
        return "--allow-unauthenticated" in command_string


@pytest.fixture
def apt_unauthenticated_packages():
    return SEC0019()


def test_apt_unauthenticated_detects_allow_unauthenticated(apt_unauthenticated_packages):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "apt-get install --allow-unauthenticated curl"},
    ]
    errors = apt_unauthenticated_packages.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "`apt` or `apt-get` is configured to allow unauthenticated packages" in errors[0]["message"]


def test_apt_unauthenticated_allows_secure_apt_get(apt_unauthenticated_packages):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "apt-get install curl"},
    ]
    errors = apt_unauthenticated_packages.check(parsed_content)
    assert len(errors) == 0


def test_apt_unauthenticated_ignores_other_instructions(apt_unauthenticated_packages):
    parsed_content = [
        {"line": 1, "instruction": "ENV", "arguments": "MY_VAR=value"},
    ]
    errors = apt_unauthenticated_packages.check(parsed_content)
    assert len(errors) == 0
