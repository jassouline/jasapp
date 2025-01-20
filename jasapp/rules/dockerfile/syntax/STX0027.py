import re
import pytest
from jasapp.rules.base_rule import BaseRule


class STX0027(BaseRule):
    """
    Rule to ensure `gem install` in RUN instructions pins gem versions.
    """
    rule_type = "dockerfile"

    def __init__(self):
        super().__init__(
            friendly_name="PinVersionsInGemInstall",
            hadolint="DL3028",
            name="STX0027",
            description="Pin versions in gem install. Instead of `gem install <gem>` use `gem install <gem>:<version>`",
            severity="warning",
        )

    def check(self, instructions):
        """
        Checks if `gem install` in RUN instructions pins gem versions.

        Args:
            instructions (list): A list of dictionaries containing parsed Dockerfile instructions.

        Returns:
            list: A list of errors found, each as a dictionary with line, message, and severity.
        """
        errors = []

        for instr in instructions:
            if instr["instruction"] == "RUN":
                commands = self.split_commands(instr["arguments"])
                for command in commands:
                    gems = self.extract_gems(command)
                    for gem in gems:
                        if ":" not in gem:
                            errors.append({
                                "line": instr["line"],
                                "message": f"Pin versions in gem install. Instead of `gem install {gem}` "
                                           f"use `gem install {gem}:<version>`",
                                "severity": self.severity,
                                "doc_link": f"https://github.com/jassouline/jasapp/wiki/{self.name}"
                            })

        return errors

    def split_commands(self, command_string):
        """
        Splits a command string into multiple commands based on && and ; delimiters.

        Args:
            command_string (str): The command string to split.

        Returns:
            list: A list of individual commands.
        """
        commands = re.split(r"[;&]", command_string)
        return [command.strip() for command in commands if command.strip()]

    def extract_gems(self, command_string):
        """
        Extract gem names from a shell command string.

        Args:
            command_string (str): The shell command string.

        Returns:
            list: A list of gem names that are unpinned.
        """

        if "gem install" not in command_string:
            return []

        args = re.split(r"\s+", command_string)
        gems = []
        in_gem_install = False
        skip_next = False
        i = 0

        while i < len(args):
            arg = args[i]

            if skip_next:
                skip_next = False
                i += 1
                continue

            if arg == "gem" and i + 1 < len(args) and args[i + 1] == "install":
                in_gem_install = True
                i += 2
                continue

            if not in_gem_install:
                i += 1
                continue

            if arg.startswith("-") and arg not in ["-v", "--version"]:
                skip_next = True if i + 1 < len(args) else False
                i += 1
                continue

            if arg in ["-v", "--version"] and i + 1 < len(args):
                if not args[i + 1].startswith("-"):
                    skip_next = True
                    i += 2
                    continue
                else:
                    i += 1
                    continue

            if ":" in arg:
                # Gem is versioned, skip it
                i += 1
                continue

            if not arg.startswith("--"):
                # Add the gem if it is not versioned
                gems.append(arg)

            i += 1

        return gems


@pytest.fixture
def pin_versions_in_gem_install():
    return STX0027()


def test_pin_versions_detects_unpinned_gem(pin_versions_in_gem_install):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "gem install rails"},
    ]
    errors = pin_versions_in_gem_install.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "Pin versions in gem install" in errors[0]["message"]


def test_pin_versions_allows_pinned_gem(pin_versions_in_gem_install):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "gem install rails:6.0.0"},
    ]
    errors = pin_versions_in_gem_install.check(parsed_content)
    assert len(errors) == 0


def test_pin_versions_detects_multiple_unpinned_gems(pin_versions_in_gem_install):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "gem install rails bundler"},
    ]
    errors = pin_versions_in_gem_install.check(parsed_content)
    assert len(errors) == 2
    assert errors[0]["line"] == 1
    assert "rails" in errors[0]["message"]
    assert errors[1]["line"] == 1
    assert "bundler" in errors[1]["message"]


def test_pin_versions_ignores_gems_in_other_commands(pin_versions_in_gem_install):
    parsed_content = [
        {"line": 1, "instruction": "ENV", "arguments": "GEM_PATH=/usr/local/bundle"},
    ]
    errors = pin_versions_in_gem_install.check(parsed_content)
    assert len(errors) == 0


def test_pin_versions_handles_complex_command(pin_versions_in_gem_install):
    parsed_content = [
        {
            "line": 1,
            "instruction": "RUN",
            "arguments": "gem install -v '>= 1.0' --no-document rails && gem install bundler",
        },
    ]
    errors = pin_versions_in_gem_install.check(parsed_content)
    assert len(errors) == 1
    assert "bundler" in errors[0]["message"]


def test_pin_versions_handles_complex_command_with_semicolon(pin_versions_in_gem_install):
    parsed_content = [
        {
            "line": 1,
            "instruction": "RUN",
            "arguments": "gem install -v '>= 1.0' --no-document rails; gem install bundler",
        },
    ]
    errors = pin_versions_in_gem_install.check(parsed_content)
    assert len(errors) == 1
    assert "bundler" in errors[0]["message"]


def test_pin_versions_handles_multiple_options(pin_versions_in_gem_install):
    parsed_content = [
        {
            "line": 1,
            "instruction": "RUN",
            "arguments": "gem install --no-document rails -v '~> 6.0.0' && gem install bundler",
        },
    ]
    errors = pin_versions_in_gem_install.check(parsed_content)
    assert len(errors) == 1
    assert "bundler" in errors[0]["message"]
