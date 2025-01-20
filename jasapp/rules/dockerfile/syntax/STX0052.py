import pytest
from jasapp.rules.base_rule import BaseRule


class STX0052(BaseRule):
    """
    Rule to ensure `yarn cache clean` is present after `yarn install` in RUN instructions.
    """
    rule_type = "dockerfile"

    def __init__(self):
        super().__init__(
            friendly_name="YarnCacheCleanAfterInstall",
            hadolint="DL3060",
            name="STX0052",
            description="`yarn cache clean` missing after `yarn install` was run.",
            severity="info",
        )

    def check(self, instructions):
        """
        Checks if `yarn cache clean` is present after `yarn install` in RUN instructions.

        Args:
            instructions (list): A list of dictionaries containing parsed Dockerfile instructions.

        Returns:
            list: A list of errors found, each as a dictionary with line, message, and severity.
        """
        errors = []

        has_yarn_install = False

        for instr in instructions:
            if instr["instruction"] == "RUN":
                if self.has_yarn_install(instr["arguments"]) and not has_yarn_install:
                    has_yarn_install = True

                if self.has_yarn_cache_clean(instr["arguments"]):
                    has_yarn_install = False

                if has_yarn_install and not self.has_yarn_cache_clean(instr["arguments"]):
                    errors.append({
                        "line": instr["line"],
                        "message": "`yarn cache clean` missing after `yarn install` was run.",
                        "severity": self.severity,
                        "doc_link": f"https://github.com/jassouline/jasapp/wiki/{self.name}"
                    })
                    has_yarn_install = False  # Reset on error found

        return errors

    def has_yarn_install(self, command_string):
        """
        Checks if a command string contains a `yarn install` command.

        Args:
            command_string (str): The command string to check.

        Returns:
            bool: True if a `yarn install` command is found, False otherwise.
        """
        return "yarn" in command_string and "install" in command_string

    def has_yarn_cache_clean(self, command_string):
        """
        Checks if a command string contains a `yarn cache clean` command.

        Args:
            command_string (str): The command string to check.

        Returns:
            bool: True if a `yarn cache clean` command is found, False otherwise.
        """
        return "yarn" in command_string and "cache clean" in command_string


@pytest.fixture
def yarn_cache_clean_after_install():
    return STX0052()


def test_yarn_cache_clean_detects_missing_clean(yarn_cache_clean_after_install):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "yarn install"},
        {"line": 2, "instruction": "RUN", "arguments": "yarn install"},
    ]
    errors = yarn_cache_clean_after_install.check(parsed_content)
    assert len(errors) == 2
    assert errors[0]["line"] == 1
    assert errors[1]["line"] == 2
    assert "`yarn cache clean` missing after `yarn install`" in errors[0]["message"]


def test_yarn_cache_clean_allows_cache_clean(yarn_cache_clean_after_install):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "yarn install && yarn cache clean"},
    ]
    errors = yarn_cache_clean_after_install.check(parsed_content)
    assert len(errors) == 0


def test_yarn_cache_clean_ignores_other_commands(yarn_cache_clean_after_install):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "echo hello"},
    ]
    errors = yarn_cache_clean_after_install.check(parsed_content)
    assert len(errors) == 0


def test_yarn_cache_clean_handles_complex_commands(yarn_cache_clean_after_install):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "yarn install && yarn add package && yarn cache clean"},
        {"line": 2, "instruction": "RUN", "arguments": "yarn install"},
    ]
    errors = yarn_cache_clean_after_install.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 2
    assert "`yarn cache clean` missing after `yarn install`" in errors[0]["message"]


def test_yarn_cache_clean_handles_complex_commands_with_semicolon(yarn_cache_clean_after_install):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "yarn install; yarn add package; yarn cache clean"},
        {"line": 2, "instruction": "RUN", "arguments": "yarn install"},
    ]
    errors = yarn_cache_clean_after_install.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 2
    assert "`yarn cache clean` missing after `yarn install`" in errors[0]["message"]
