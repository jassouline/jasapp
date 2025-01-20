import pytest
from jasapp.rules.base_rule import BaseRule


class SEC0022(BaseRule):
    """
    Rule to detect if `apt-get install` is used without `-y` or with `--force-yes` or `--allow-unauthenticated`.
    """
    rule_type = "dockerfile"

    def __init__(self):
        super().__init__(
            friendly_name="AptGetInstallDangerousOptions",
            name="SEC0022",
            description="`apt-get install` is used without `-y` or with `--force-yes` or `--allow-unauthenticated`, which can bypass prompts and verifications.",
            severity="error",
        )

    def check(self, instructions):
        """
        Checks if `apt-get install` commands in `RUN` instructions are used without `-y` or with `--force-yes` or `--allow-unauthenticated`.

        Args:
            instructions (list): A list of dictionaries containing parsed Dockerfile instructions.

        Returns:
            list: A list of errors found, each as a dictionary with line, message, and severity.
        """
        errors = []

        for instr in instructions:
            if instr["instruction"] == "RUN":
                if self.is_apt_get_install_dangerous(instr["arguments"]):
                    errors.append({
                        "line": instr["line"],
                        "message": "`apt-get install` is used without `-y` or with `--force-yes` or `--allow-unauthenticated`, which can bypass prompts and verifications.",
                        "severity": self.severity,
                        "doc_link": f"https://github.com/jassouline/jasapp/wiki/{self.name}"
                    })

        return errors

    def is_apt_get_install_dangerous(self, command_string):
        """
        Checks if a command string contains an `apt-get install` command without `-y` or with `--force-yes` or `--allow-unauthenticated`.

        Args:
            command_string (str): The command string to check.

        Returns:
            bool: True if `apt-get install` is used without `-y` or with dangerous options, False otherwise.
        """
        if "apt-get install" not in command_string:
            return False

        # Check for absence of -y and presence of --force-yes or --allow-unauthenticated
        if ("--force-yes" in command_string or "--allow-unauthenticated" in command_string):
            return True

        if ("-y" not in command_string and "--assume-yes" not in command_string):
            return True

        return False


@pytest.fixture
def apt_get_install_dangerous_options():
    return SEC0022()


def test_apt_get_install_dangerous_detects_force_yes(apt_get_install_dangerous_options):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "apt-get install --force-yes curl"},
    ]
    errors = apt_get_install_dangerous_options.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "`apt-get install` is used without `-y` or with `--force-yes`" in errors[0]["message"]


def test_apt_get_install_dangerous_detects_allow_unauthenticated(apt_get_install_dangerous_options):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "apt-get install --allow-unauthenticated curl"},
    ]
    errors = apt_get_install_dangerous_options.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "`apt-get install` is used without `-y` or with `--force-yes`" in errors[0]["message"]


def test_apt_get_install_dangerous_detects_missing_y(apt_get_install_dangerous_options):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "apt-get install curl"},
    ]
    errors = apt_get_install_dangerous_options.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "`apt-get install` is used without `-y` or with `--force-yes`" in errors[0]["message"]


def test_apt_get_install_dangerous_allows_safe_options(apt_get_install_dangerous_options):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "apt-get install -y curl"},
    ]
    errors = apt_get_install_dangerous_options.check(parsed_content)
    assert len(errors) == 0


def test_apt_get_install_dangerous_ignores_other_instructions(apt_get_install_dangerous_options):
    parsed_content = [
        {"line": 1, "instruction": "ENV", "arguments": "MY_VAR=value"},
    ]
    errors = apt_get_install_dangerous_options.check(parsed_content)
    assert len(errors) == 0
