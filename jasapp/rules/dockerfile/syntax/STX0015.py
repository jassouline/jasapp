import pytest
from jasapp.rules.base_rule import BaseRule


class STX0015(BaseRule):
    """
    Rule to ensure the `--no-install-recommends` flag is used in `apt-get install` commands.
    """
    rule_type = "dockerfile"

    def __init__(self):
        super().__init__(
            friendly_name="AvoidInstallRecommends",
            hadolint="DL3015",
            name="STX0015",
            description=(
                "Avoid additional packages by specifying `--no-install-recommends` in `apt-get install` commands."
            ),
            severity="info",
        )

    def check(self, instructions):
        """
        Checks if `apt-get install` commands use the `--no-install-recommends` flag.

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
                    if self.is_apt_get_install(command) and not self.has_no_install_recommends(command):
                        errors.append({
                            "line": instr["line"],
                            "message": (
                                "Avoid additional packages by specifying `--no-install-recommends` in `apt-get install` commands."
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
    def has_no_install_recommends(command):
        """
        Check if a command includes the `--no-install-recommends` flag or equivalent.

        Args:
            command (str): The command to check.

        Returns:
            bool: True if the command disables recommendations, False otherwise.
        """
        return "--no-install-recommends" in command or "APT::Install-Recommends=false" in command


@pytest.fixture
def avoid_install_recommends():
    return STX0015()


def test_avoid_install_recommends_detects_missing_flag(avoid_install_recommends):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "apt-get install curl"},
        {"line": 2, "instruction": "RUN", "arguments": "apt-get install -y vim"},
    ]
    errors = avoid_install_recommends.check(parsed_content)
    assert len(errors) == 2
    assert errors[0]["message"] == (
        "Avoid additional packages by specifying `--no-install-recommends` in `apt-get install` commands."
    )
    assert errors[0]["line"] == 1
    assert errors[1]["line"] == 2


def test_avoid_install_recommends_allows_flag(avoid_install_recommends):
    parsed_content = [
        {"line": 3, "instruction": "RUN", "arguments": "apt-get install --no-install-recommends curl"},
        {"line": 4, "instruction": "RUN", "arguments": "apt-get install -y --no-install-recommends vim"},
    ]
    errors = avoid_install_recommends.check(parsed_content)
    assert len(errors) == 0


def test_avoid_install_recommends_allows_apt_config(avoid_install_recommends):
    parsed_content = [
        {"line": 5, "instruction": "RUN", "arguments": "apt-get install -o APT::Install-Recommends=false curl"},
    ]
    errors = avoid_install_recommends.check(parsed_content)
    assert len(errors) == 0


def test_avoid_install_recommends_handles_multiline_commands(avoid_install_recommends):
    parsed_content = [
        {"line": 6, "instruction": "RUN", "arguments": "apt-get install curl \\\n    --no-install-recommends"},
    ]
    errors = avoid_install_recommends.check(parsed_content)
    assert len(errors) == 0
